import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
// @ts-expect-error: plain JavaScript script, no type declarations.
import { checkPackage, INSTALL_SCRIPTS, readExpected } from "../scripts/check-package.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const expected: string[] = readExpected(readFileSync(join(ROOT, "scripts", "package-files.txt"), "utf8"));

describe("package contents check", () => {
  it("accepts the exact expected file list with no install scripts", () => {
    expect(checkPackage({ files: [...expected], scripts: { build: "tsc" }, bundled: [] }, expected)).toEqual([]);
  });

  it("reports a missing file and an unexpected file", () => {
    const files = [...expected.slice(1), "dist/debug.log"];
    expect(checkPackage({ files, scripts: {}, bundled: [] }, expected)).toEqual([
      `missing from the package: ${expected[0]}`,
      "not in the expected list: dist/debug.log",
    ]);
  });

  it.each(INSTALL_SCRIPTS as string[])("refuses a %s script", (name) => {
    expect(checkPackage({ files: [...expected], scripts: { [name]: "node x.js" }, bundled: [] }, expected))
      .toEqual([`install-time script would ship: ${name}`]);
  });

  it("refuses a binding.gyp and bundled dependencies", () => {
    const files = [...expected, "binding.gyp"];
    expect(checkPackage({ files, scripts: {}, bundled: ["left-pad"] }, [...expected, "binding.gyp"])).toEqual([
      "native build file would ship: binding.gyp",
      "bundled dependencies would ship: left-pad",
    ]);
  });

  it("keeps the expected list sorted, unique and inside the published paths", () => {
    expect(expected).toEqual([...new Set(expected)].sort());
    const { files: published } = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")) as { files: string[] };
    for (const path of expected) {
      expect(path === "package.json" || published.some((p) => path === p || path.startsWith(`${p}/`))).toBe(true);
    }
  });

  it("ships no install-time script in this package.json", () => {
    const { scripts } = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")) as { scripts: Record<string, string> };
    for (const name of INSTALL_SCRIPTS as string[]) expect(Object.hasOwn(scripts, name)).toBe(false);
  });
});
