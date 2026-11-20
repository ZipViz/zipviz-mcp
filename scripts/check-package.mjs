#!/usr/bin/env node
// Checks what `npm pack` would publish, so a release can't ship an unexpected
// file or an install-time script by accident.
//
//   npm run build && npm run check:package            check
//   npm run build && npm run check:package -- --update  rewrite the expected list
//
// The expected list is scripts/package-files.txt, one path per line. Run it
// after a clean build: stale files in dist/ would otherwise show up as extra.

import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const EXPECTED_PATH = join(ROOT, "scripts", "package-files.txt");

// Scripts npm runs on the consumer's machine when the package is installed
// (prepare also runs for git installs). None of them may ship.
export const INSTALL_SCRIPTS = Object.freeze([
  "preinstall", "install", "postinstall", "preprepare", "prepare", "postprepare",
]);

export function readExpected(text) {
  return text.split("\n").map((line) => line.trim()).filter((line) => line.length > 0);
}

export function checkPackage({ files, scripts, bundled }, expected) {
  const problems = [];
  const actual = new Set(files);
  const wanted = new Set(expected);
  for (const path of expected) if (!actual.has(path)) problems.push(`missing from the package: ${path}`);
  for (const path of files) if (!wanted.has(path)) problems.push(`not in the expected list: ${path}`);
  for (const name of INSTALL_SCRIPTS) {
    if (scripts && Object.hasOwn(scripts, name)) problems.push(`install-time script would ship: ${name}`);
  }
  // npm runs `node-gyp rebuild` on install when binding.gyp is present, even with no install script.
  for (const path of files) if (path === "binding.gyp" || path.endsWith("/binding.gyp")) {
    problems.push(`native build file would ship: ${path}`);
  }
  if (Array.isArray(bundled) && bundled.length > 0) problems.push(`bundled dependencies would ship: ${bundled.join(", ")}`);
  return problems;
}

// `npm pack --json` returns an array of one result up to npm 11, and an object
// keyed by package name from npm 12. Accept exactly one well-formed result in
// either shape; anything else is an error, never a guess.
export function parsePackJson(text, packageName) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("npm pack output is not JSON");
  }
  let results;
  if (Array.isArray(parsed)) {
    results = parsed;
  } else if (parsed !== null && typeof parsed === "object") {
    const keys = Object.keys(parsed);
    if (keys.length !== 1 || keys[0] !== packageName) {
      throw new Error(`npm pack output must hold exactly one result, for ${packageName}`);
    }
    results = [parsed[packageName]];
  } else {
    throw new Error("npm pack output has an unknown shape");
  }
  if (results.length !== 1) throw new Error("npm pack output must hold exactly one result");
  const [result] = results;
  if (result === null || typeof result !== "object" || result.name !== packageName
      || !Array.isArray(result.files)
      || !result.files.every((file) => file !== null && typeof file === "object" && typeof file.path === "string")
      || (result.bundled !== undefined && !Array.isArray(result.bundled))) {
    throw new Error("npm pack result is malformed");
  }
  return { files: result.files.map((file) => file.path).sort(), bundled: result.bundled ?? [] };
}

function packResult(packageName) {
  const out = execFileSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], {
    cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "inherit"],
  });
  return parsePackJson(out, packageName);
}

function main() {
  const manifest = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
  const { files, bundled } = packResult(manifest.name);
  if (process.argv.includes("--update")) {
    writeFileSync(EXPECTED_PATH, `${files.join("\n")}\n`);
    console.log(`package contents: wrote ${files.length} paths to scripts/package-files.txt`);
    return;
  }
  const problems = checkPackage({ files, scripts: manifest.scripts, bundled }, readExpected(readFileSync(EXPECTED_PATH, "utf8")));
  if (problems.length > 0) {
    for (const problem of problems) console.error(`package contents: ${problem}`);
    console.error("If the change is intended, rebuild from clean and run: npm run check:package -- --update");
    process.exit(1);
  }
  console.log(`package contents: ok (${files.length} files)`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
