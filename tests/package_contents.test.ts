import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
// @ts-expect-error: plain JavaScript script, no type declarations.
import { checkPackage, INSTALL_SCRIPTS, parsePackJson, readExpected } from "../scripts/check-package.mjs";

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

  describe("npm pack JSON", () => {
    const result = {
      name: "zipviz-mcp",
      version: "2.0.1",
      files: [{ path: "package.json", size: 1, mode: 420 }, { path: "LICENSE", size: 1, mode: 420 }],
      bundled: [],
    };
    const parsed = { files: ["LICENSE", "package.json"], bundled: [] };

    it("reads the npm 10 and 11 array shape", () => {
      expect(parsePackJson(JSON.stringify([result]), "zipviz-mcp")).toEqual(parsed);
    });

    it("reads the npm 12 shape keyed by package name", () => {
      expect(parsePackJson(JSON.stringify({ "zipviz-mcp": result }), "zipviz-mcp")).toEqual(parsed);
    });

    it.each([
      ["not JSON", "npm notice"],
      ["an empty array", "[]"],
      ["two array results", JSON.stringify([result, result])],
      ["an empty object", "{}"],
      ["two keyed results", JSON.stringify({ "zipviz-mcp": result, other: { ...result, name: "other" } })],
      ["a different package key", JSON.stringify({ other: result })],
      ["a result for a different package", JSON.stringify([{ ...result, name: "other" }])],
      ["files that are not a list", JSON.stringify([{ ...result, files: "dist" }])],
      ["a file without a path", JSON.stringify([{ ...result, files: [{ size: 1 }] }])],
      ["bundled that is not a list", JSON.stringify([{ ...result, bundled: "x" }])],
      ["a bare number", "42"],
      ["null", "null"],
    ])("refuses %s", (_label, text) => {
      expect(() => parsePackJson(text, "zipviz-mcp")).toThrow();
    });
  });
});
