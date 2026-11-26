#!/usr/bin/env node
// Creates one GitHub Release per version, with notes built from the titles of
// the pull requests merged since the previous release. No dependencies: Node's
// fetch, the GitHub REST API and the local git history.
//
//   node .github/scripts/release-notes.mjs --version 2.0.0 --target <sha> \
//     --version-file package.json [--ancestor-of <sha>] [--new-tag] [--dry-run]
//
// The version must match the version file at the target commit. A release that
// already exists for the tag is left alone, so the script is safe to re-run.
// `--ancestor-of` requires the target to be that commit or one of its
// ancestors (a manual run passes the tip of main, so an earlier commit can be
// released, but nothing off main). `--new-tag` requires that no tag for the
// version exists yet (a manual run creates the tag).

import { execFileSync } from "node:child_process";
import { pathToFileURL } from "node:url";

const SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?$/;

/** Parses "1.2.3" or "1.2.3-rc.1" (no leading "v"); returns null for anything else. */
export function parseVersion(text) {
  const m = SEMVER.exec(String(text ?? "").trim());
  if (!m) return null;
  return { major: +m[1], minor: +m[2], patch: +m[3], pre: m[4] ?? "" };
}

/** Orders two parsed versions; a prerelease sorts before its release. */
export function compareVersions(a, b) {
  for (const k of ["major", "minor", "patch"]) if (a[k] !== b[k]) return a[k] - b[k];
  if (a.pre === b.pre) return 0;
  if (!a.pre) return 1;
  if (!b.pre) return -1;
  return a.pre < b.pre ? -1 : 1;
}

/** The newest existing release tag older than `version`, or null for the first release. */
export function previousTag(tags, version) {
  const current = parseVersion(version);
  let best = null;
  for (const tag of tags) {
    if (!tag.startsWith("v")) continue;
    const v = parseVersion(tag.slice(1));
    if (!v || compareVersions(v, current) >= 0) continue;
    if (!best || compareVersions(v, best.v) > 0) best = { tag, v };
  }
  return best?.tag ?? null;
}

/** Reads the version from package.json (`version`) or an OpenAPI file (`info.version`). */
export function versionFromFile(json) {
  const data = JSON.parse(json);
  return typeof data.version === "string" ? data.version : data?.info?.version;
}

/**
 * One line of release notes from a pull request title: trimmed, single-spaced,
 * no em or en dashes (house style), no HTML, and no live @mentions (a release
 * would notify them).
 */
export function cleanTitle(title) {
  return String(title)
    .replace(/\s+/g, " ")
    .trim()
    .replace(/\s*[\u2014\u2013]\s*/g, ", ")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/(^|[^\w`])@([A-Za-z0-9][\w-]*(?:\/[\w.-]+)?)/g, "$1`@$2`");
}

const isBot = (pr) => pr.user?.type === "Bot" || /\[bot\]$/.test(pr.user?.login ?? "");

/**
 * The release body. `pulls` are the merged pull requests in this release, any
 * order. People's changes are listed oldest first; bot dependency updates are
 * counted on one line.
 */
export function buildNotes({ repo, tag, previous, pulls }) {
  const people = pulls.filter((pr) => !isBot(pr)).sort((a, b) => a.merged_at.localeCompare(b.merged_at));
  const bots = pulls.length - people.length;
  const lines = ["## Changes", ""];
  for (const pr of people) lines.push(`- ${cleanTitle(pr.title)} (#${pr.number})`);
  if (bots) lines.push(`- Dependency updates: ${bots} automated pull request${bots === 1 ? "" : "s"}`);
  if (!pulls.length) lines.push(previous ? `No pull requests were merged since ${previous}.` : "No merged pull requests.");
  if (previous) lines.push("", `Full list of changes: https://github.com/${repo}/compare/${previous}...${tag}`);
  return lines.join("\n") + "\n";
}

function git(...args) {
  return execFileSync("git", args, { encoding: "utf8" }).trim();
}

/**
 * Checks the commit a release goes on, before anything is created. `run` runs
 * git (injectable so the tests can point it at a scratch repository). Throws
 * with the reason; returns the list of local v* tags.
 */
export function checkTarget({ target, version, versionFile = "package.json", ancestorOf, newTag }, run = git) {
  if (!target || !/^[0-9a-f]{40}$/.test(target)) throw new Error("--target must be a full commit SHA");
  let type;
  try {
    type = run("cat-file", "-t", target);
  } catch {
    type = "";
  }
  if (type !== "commit") throw new Error(`${target.slice(0, 8)} is not a commit in this repository`);
  if (ancestorOf !== undefined) {
    if (!/^[0-9a-f]{40}$/.test(ancestorOf)) throw new Error("--ancestor-of must be a full commit SHA");
    try {
      run("merge-base", "--is-ancestor", target, ancestorOf);
    } catch {
      throw new Error(`${target.slice(0, 8)} is not on main (not an ancestor of ${ancestorOf.slice(0, 8)})`);
    }
  }
  const fileVersion = versionFromFile(run("show", `${target}:${versionFile}`));
  if (fileVersion !== version) throw new Error(`${versionFile} at ${target.slice(0, 8)} says ${fileVersion}, not ${version}`);
  const tags = run("tag", "--list", "v*").split("\n").filter(Boolean);
  const tag = `v${version}`;
  if (tags.includes(tag)) {
    if (newTag) throw new Error(`tag ${tag} already exists`);
    if (run("rev-list", "-n", "1", tag) !== target) throw new Error(`tag ${tag} already points at another commit`);
  }
  return tags;
}

async function api(path, { method = "GET", body } = {}) {
  const res = await fetch(`https://api.github.com${path}`, {
    method,
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
      "X-GitHub-Api-Version": "2022-11-28",
      ...(body ? { "Content-Type": "application/json" } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (res.status === 404 && method === "GET") return null;
  if (!res.ok) throw new Error(`GitHub API ${method} ${path}: HTTP ${res.status}`);
  return res.json();
}

/** All merged pull requests into the default branch (small public repos, so a few pages at most). */
async function mergedPulls(repo, base) {
  const out = [];
  for (let page = 1; page <= 20; page++) {
    const batch = await api(`/repos/${repo}/pulls?state=closed&base=${encodeURIComponent(base)}&per_page=100&page=${page}`);
    if (!batch?.length) break;
    out.push(...batch.filter((pr) => pr.merged_at && pr.merge_commit_sha));
    if (batch.length < 100) break;
  }
  return out;
}

const VALUE_FLAGS = { "--version": "version", "--target": "target", "--version-file": "versionFile", "--base": "base",
  "--ancestor-of": "ancestorOf" };

export function parseArgs(argv) {
  const out = { dryRun: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--dry-run") out.dryRun = true;
    else if (a === "--new-tag") out.newTag = true;
    else if (VALUE_FLAGS[a] && i + 1 < argv.length) out[VALUE_FLAGS[a]] = argv[++i];
    else throw new Error(`unknown or incomplete argument ${a}`);
  }
  return out;
}

async function main() {
  const opt = parseArgs(process.argv.slice(2));
  const repo = process.env.GITHUB_REPOSITORY;
  const version = String(opt.version ?? "").replace(/^v/, "");
  if (!parseVersion(version)) throw new Error(`not a version: ${JSON.stringify(opt.version)}`);
  if (!repo || !/^[\w.-]+\/[\w.-]+$/.test(repo)) throw new Error("GITHUB_REPOSITORY is not set");
  const tag = `v${version}`;
  const base = opt.base ?? "main";

  if (await api(`/repos/${repo}/releases/tags/${encodeURIComponent(tag)}`)) {
    console.log(`Release ${tag} already exists; nothing to do.`);
    return;
  }
  const tags = checkTarget({ target: opt.target, version, versionFile: opt.versionFile, ancestorOf: opt.ancestorOf,
    newTag: opt.newTag });
  const previous = previousTag(tags, version);
  const range = previous ? `${previous}..${opt.target}` : opt.target;
  const inRelease = new Set(git("rev-list", range).split("\n").filter(Boolean));
  const pulls = (await mergedPulls(repo, base)).filter((pr) => inRelease.has(pr.merge_commit_sha));
  const body = buildNotes({ repo, tag, previous, pulls });

  console.log(`${tag} at ${opt.target}, previous ${previous ?? "none"}, ${pulls.length} pull requests\n\n${body}`);
  if (opt.dryRun) return;
  const release = await api(`/repos/${repo}/releases`, {
    method: "POST",
    body: { tag_name: tag, target_commitish: opt.target, name: tag, body, draft: false, prerelease: !!parseVersion(version).pre },
  });
  console.log(`Created ${release.html_url}`);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  main().catch((err) => {
    console.error(`release-notes: ${err.message}`);
    process.exit(1);
  });
}
