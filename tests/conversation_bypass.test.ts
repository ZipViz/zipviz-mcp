import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const ROOT=fileURLToPath(new URL("..",import.meta.url));

describe("M4a one-shot bypass fence", () => {
  it("keeps zipviz_send restricted to envelope V2 with no conversation input", async () => {
    const source=await readFile(`${ROOT}/src/tools/send.ts`,"utf8");
    expect(source).toContain(".literal(2)");
    expect(source).not.toMatch(/conversation\s*:/u);
    expect(source).not.toContain("signEnvelopeV3");
  });
});
