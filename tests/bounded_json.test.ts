import { describe, expect, it } from "vitest";
import { BodyTooLargeError, readJsonBounded } from "../src/lib/bounded-json.js";

function streamOf(...chunks: string[]): ReadableStream<Uint8Array> {
  return new ReadableStream({
    start(controller) {
      for (const c of chunks) controller.enqueue(new TextEncoder().encode(c));
      controller.close();
    },
  });
}

describe("readJsonBounded", () => {
  it("parses a body inside the ceiling", async () => {
    await expect(readJsonBounded(new Response(streamOf('{"a":', "1}")), 64)).resolves.toEqual({ a: 1 });
  });

  it("refuses a streamed body past the ceiling, whatever Content-Length says", async () => {
    const big = "x".repeat(100);
    await expect(readJsonBounded(new Response(streamOf(`"${big}`, `${big}"`)), 64)).rejects.toBeInstanceOf(
      BodyTooLargeError
    );
  });

  it("refuses up front when the declared length is over the ceiling", async () => {
    const res = new Response(streamOf("{}"), { headers: { "content-length": "1000000" } });
    await expect(readJsonBounded(res, 64)).rejects.toBeInstanceOf(BodyTooLargeError);
  });

  it("still rejects malformed JSON inside the ceiling", async () => {
    await expect(readJsonBounded(new Response(streamOf("{nope")), 64)).rejects.toBeInstanceOf(SyntaxError);
  });
});
