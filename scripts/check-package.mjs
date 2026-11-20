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

function packResult() {
  const out = execFileSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], {
    cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "inherit"],
  });
  const [result] = JSON.parse(out);
  return { files: result.files.map((file) => file.path).sort(), bundled: result.bundled ?? [] };
}

function main() {
  const { files, bundled } = packResult();
  if (process.argv.includes("--update")) {
    writeFileSync(EXPECTED_PATH, `${files.join("\n")}\n`);
    console.log(`package contents: wrote ${files.length} paths to scripts/package-files.txt`);
    return;
  }
  const { scripts } = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
  const problems = checkPackage({ files, scripts, bundled }, readExpected(readFileSync(EXPECTED_PATH, "utf8")));
  if (problems.length > 0) {
    for (const problem of problems) console.error(`package contents: ${problem}`);
    console.error("If the change is intended, rebuild from clean and run: npm run check:package -- --update");
    process.exit(1);
  }
  console.log(`package contents: ok (${files.length} files)`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
