// Run with: node --test .github/scripts/release-notes.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildNotes, checkTarget, cleanTitle, compareVersions, parseArgs, parseVersion, previousTag, versionFromFile } from "./release-notes.mjs";

test("parseVersion accepts plain and prerelease versions only", () => {
  assert.deepEqual(parseVersion("2.0.0"), { major: 2, minor: 0, patch: 0, pre: "" });
  assert.equal(parseVersion("2.0.0-rc.1").pre, "rc.1");
  for (const bad of ["v2.0.0", "2.0", "02.0.0", "2.0.0;rm -rf", "", undefined]) assert.equal(parseVersion(bad), null, String(bad));
});

test("compareVersions orders releases and puts a prerelease before its release", () => {
  const sorted = ["1.10.0", "1.2.0", "2.0.0-rc.1", "2.0.0", "1.1.1"].map(parseVersion).sort(compareVersions);
  assert.deepEqual(sorted.map((v) => `${v.major}.${v.minor}.${v.patch}${v.pre ? "-" + v.pre : ""}`), ["1.1.1", "1.2.0", "1.10.0", "2.0.0-rc.1", "2.0.0"]);
});

test("previousTag finds the newest older release tag and ignores other tags", () => {
  assert.equal(previousTag(["v1.1.1", "v1.10.0", "v2.1.0", "latest", "vnext"], "2.0.0"), "v1.10.0");
  assert.equal(previousTag([], "2.0.0"), null);
  assert.equal(previousTag(["v2.0.0"], "2.0.0"), null);
});

test("versionFromFile reads package.json and OpenAPI files", () => {
  assert.equal(versionFromFile('{"name":"x","version":"2.0.0"}'), "2.0.0");
  assert.equal(versionFromFile('{"openapi":"3.1.0","info":{"version":"1.0.0"}}'), "1.0.0");
  assert.equal(versionFromFile("{}"), undefined);
});

test("cleanTitle keeps the title factual and safe to publish", () => {
  assert.equal(cleanTitle("  Add   a quickstart  "), "Add a quickstart");
  assert.equal(cleanTitle("Release 2.0.0 \u2014 new tools"), "Release 2.0.0, new tools");
  assert.equal(cleanTitle("Range 1\u20132"), "Range 1, 2");
  assert.equal(cleanTitle("Escape <script>"), "Escape &lt;script&gt;");
  assert.equal(cleanTitle("Thanks @someone and @org/team"), "Thanks `@someone` and `@org/team`");
  assert.equal(cleanTitle("mail me at a@b.com"), "mail me at a@b.com");
});

const pr = (number, title, merged_at, login = "person", type = "User") => ({ number, title, merged_at, user: { login, type } });

test("buildNotes lists people's pull requests oldest first and counts bot updates", () => {
  const notes = buildNotes({
    repo: "ZipViz/zipviz-mcp",
    tag: "v2.0.0",
    previous: "v1.1.1",
    pulls: [
      pr(11, "Release zipviz-mcp 2.0.0", "2026-11-18T08:55:49Z"),
      pr(12, "build(deps): bump x", "2026-11-17T00:00:00Z", "dependabot[bot]", "Bot"),
      pr(10, "Add an npx quickstart", "2026-10-19T19:47:17Z"),
    ],
  });
  assert.equal(
    notes,
    [
      "## Changes",
      "",
      "- Add an npx quickstart (#10)",
      "- Release zipviz-mcp 2.0.0 (#11)",
      "- Dependency updates: 1 automated pull request",
      "",
      "Full list of changes: https://github.com/ZipViz/zipviz-mcp/compare/v1.1.1...v2.0.0",
      "",
    ].join("\n"),
  );
});

test("buildNotes for a first release has no compare link", () => {
  const notes = buildNotes({ repo: "ZipViz/zipviz-cli", tag: "v0.1.0", previous: null, pulls: [pr(1, "First", "2026-10-01T00:00:00Z")] });
  assert.ok(!notes.includes("compare"));
  assert.ok(notes.includes("- First (#1)"));
  assert.ok(buildNotes({ repo: "a/b", tag: "v1.0.1", previous: "v1.0.0", pulls: [] }).includes("No pull requests were merged since v1.0.0."));
});

test("parseArgs takes the known flags only", () => {
  assert.deepEqual(parseArgs(["--version", "2.0.0", "--target", "abc", "--version-file", "openapi.json", "--dry-run"]), {
    dryRun: true,
    version: "2.0.0",
    target: "abc",
    versionFile: "openapi.json",
  });
  assert.deepEqual(parseArgs(["--ancestor-of", "def", "--new-tag"]), { dryRun: false, ancestorOf: "def", newTag: true });
  assert.throws(() => parseArgs(["--tag", "v1"]));
  assert.throws(() => parseArgs(["--version"]));
});

// A scratch repository: main has 2.0.0, then 2.0.1; a side branch has 2.0.0 too.
function scratchRepo() {
  const dir = mkdtempSync(join(tmpdir(), "release-notes-"));
  const run = (...args) => execFileSync("git", ["-C", dir, ...args], { encoding: "utf8" }).trim();
  run("init", "-q", "-b", "main");
  run("config", "user.email", "test@example.invalid");
  run("config", "user.name", "Test");
  const commit = (version, message) => {
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "x", version, description: message }));
    run("add", "package.json");
    run("commit", "-q", "-m", message);
    return run("rev-parse", "HEAD");
  };
  const v200 = commit("2.0.0", "Release 2.0.0");
  const v201 = commit("2.0.1", "Release 2.0.1");
  run("switch", "-q", "-c", "side", v200);
  const side = commit("2.0.0", "Side change");
  run("switch", "-q", "main");
  return { dir, run, v200, v201, side, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

test("checkTarget accepts an earlier commit on main whose version matches and has no tag", () => {
  const r = scratchRepo();
  try {
    assert.deepEqual(checkTarget({ target: r.v200, version: "2.0.0", ancestorOf: r.v201, newTag: true }, r.run), []);
    assert.deepEqual(checkTarget({ target: r.v201, version: "2.0.1", ancestorOf: r.v201, newTag: true }, r.run), []);
  } finally {
    r.cleanup();
  }
});

test("checkTarget refuses a commit off main, a version mismatch, an unknown commit and an existing tag", () => {
  const r = scratchRepo();
  try {
    assert.throws(() => checkTarget({ target: r.side, version: "2.0.0", ancestorOf: r.v201, newTag: true }, r.run), /not on main/);
    assert.throws(() => checkTarget({ target: r.v201, version: "2.0.0", ancestorOf: r.v201, newTag: true }, r.run), /says 2.0.1, not 2.0.0/);
    assert.throws(() => checkTarget({ target: "f".repeat(40), version: "2.0.0", ancestorOf: r.v201, newTag: true }, r.run), /not a commit/);
    assert.throws(() => checkTarget({ target: "HEAD", version: "2.0.1" }, r.run), /full commit SHA/);
    assert.throws(() => checkTarget({ target: r.v200, version: "2.0.0", ancestorOf: "main", newTag: true }, r.run), /full commit SHA/);
    r.run("tag", "v2.0.0", r.v200);
    assert.throws(() => checkTarget({ target: r.v200, version: "2.0.0", ancestorOf: r.v201, newTag: true }, r.run), /already exists/);
    // A pushed tag (no --new-tag) is fine on its own commit, and refused elsewhere.
    assert.deepEqual(checkTarget({ target: r.v200, version: "2.0.0" }, r.run), ["v2.0.0"]);
    r.run("tag", "v2.0.1", r.v200);
    assert.throws(() => checkTarget({ target: r.v201, version: "2.0.1" }, r.run), /another commit/);
  } finally {
    r.cleanup();
  }
});
