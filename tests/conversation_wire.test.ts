// M2 trust-boundary delta, recorded before production changes:
// - signed attribution expands over the complete ordered conversation block;
// - version and vocabulary validation happen before any ingress side effect;
// - conversation-looking V2 metadata stays untrusted and non-semantic;
// - deriveWakeCapability is the only authority for locally signed wake data;
// - each permitted vocabulary combination has an independent byte-level alarm;
// - runtime/native identifiers and capability negotiation remain outside M2.

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createPrivateKey, createPublicKey } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  AGENT_CONVERSATIONS_CAPABILITY_URI,
  AGENT_CONVERSATIONS_ENVELOPE_VERSION,
  CONVERSATION_AUTHORITY_CLAIMS,
  CONVERSATION_FIELD_ORDER,
  CONVERSATION_INTENTS,
  CONVERSATION_OUTCOME_CODES,
  CONVERSATION_STATES,
  CONVERSATION_WAKE_KINDS,
  ConversationWireError,
  deriveWakeCapability,
  encodeConversationWire,
  MAX_CONVERSATION_TURN,
  parseConversationWire,
  type ConversationWire,
  WAKE_FIELD_ORDER,
} from "../src/core/conversation-wire.js";
import {
  canonicalEnvelopeV2,
  canonicalEnvelopeV3,
  RegistryPubkeyCache,
  verifyEnvelopeV3,
} from "../src/core/envelope.js";
import { signEnvelopeV3 } from "../src/tools/sign_message.js";
import {
  AGENT_CONVERSATIONS_PROTOCOL_FIXTURE,
  FULL_CONVERSATION,
  GOAL_REF,
  MINIMAL_CONVERSATION,
  PERMITTED_WIRE_COMBINATIONS,
  WAKE_DERIVATION_VECTORS,
} from "./fixtures/conversation_wire.js";

const FROM = "zip-grok.smc.viz";
const TO = "viz-grok.smc.viz";
const MSG_ID = "msg-v3-golden-00000001";
const MESSAGE = "hello mailbox v3";
const TS = "2026-08-25T00:00:00.000Z";
const EXPIRES = "2026-08-25T00:10:00.000Z";
// RFC 8032 section 7.1 TEST 1: a published test vector, not a secret. The key
// is built at run time from the published seed.
const RFC8032_TEST1_SEED_HEX =
  "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const PRIVATE_PEM = createPrivateKey({
  key: Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    Buffer.from(RFC8032_TEST1_SEED_HEX, "hex"),
  ]),
  format: "der",
  type: "pkcs8",
})
  .export({ format: "pem", type: "pkcs8" })
  .toString();
const PUBLIC_HEX =
  "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

describe("Agent Conversations V3 wire", () => {
  it("pins the public capability family and machine envelope version", () => {
    expect(AGENT_CONVERSATIONS_CAPABILITY_URI).toBe(
      "https://zipviz.ai/protocols/agent-conversations"
    );
    expect(AGENT_CONVERSATIONS_ENVELOPE_VERSION).toBe(3);
    expect(MAX_CONVERSATION_TURN).toBe(2_147_483_647);
    expect(AGENT_CONVERSATIONS_PROTOCOL_FIXTURE).toEqual({
      capability_family_uri: AGENT_CONVERSATIONS_CAPABILITY_URI,
      envelope_version: AGENT_CONVERSATIONS_ENVELOPE_VERSION,
      max_conversation_turn: MAX_CONVERSATION_TURN,
    });
    expect(CONVERSATION_INTENTS).toEqual([
      "propose",
      "accept",
      "counter",
      "ask",
      "needs-human",
      "pause",
      "resume",
      "stall",
      "complete",
      "fail",
      "close",
    ]);
    expect(CONVERSATION_STATES).toEqual([
      "proposed",
      "active",
      "waiting-human",
      "paused",
      "stalled",
      "completed",
      "failed",
      "closed",
    ]);
    expect(CONVERSATION_OUTCOME_CODES).toEqual([
      "goal-achieved",
      "cancelled",
      "declined",
      "superseded",
      "capability-unavailable",
      "policy-blocked",
      "invalid-request",
      "internal-error",
    ]);
    expect(CONVERSATION_AUTHORITY_CLAIMS).toEqual(["propose-only", "commit"]);
    expect(CONVERSATION_WAKE_KINDS).toEqual(["push", "poll", "none"]);
  });

  it("reasserts both untouched V2 canonical goldens", () => {
    expect(
      canonicalEnvelopeV2({
        from: FROM,
        to: TO,
        msg_id: MSG_ID,
        message: MESSAGE,
        timestamp: TS,
        expires_at: EXPIRES,
      })
    ).toBe(
      '{"v":2,"from":"zip-grok.smc.viz","to":"viz-grok.smc.viz","msg_id":"msg-v3-golden-00000001","message":"hello mailbox v3","timestamp":"2026-08-25T00:00:00.000Z","expires_at":"2026-08-25T00:10:00.000Z"}'
    );
    expect(
      canonicalEnvelopeV2({
        from: FROM,
        to: TO,
        msg_id: MSG_ID,
        message: MESSAGE,
        timestamp: TS,
        expires_at: EXPIRES,
        reply_to: "msg-parent-v2-00000001",
      })
    ).toBe(
      '{"v":2,"from":"zip-grok.smc.viz","to":"viz-grok.smc.viz","msg_id":"msg-v3-golden-00000001","message":"hello mailbox v3","timestamp":"2026-08-25T00:00:00.000Z","expires_at":"2026-08-25T00:10:00.000Z","reply_to":"msg-parent-v2-00000001"}'
    );
  });

  it("has minimal and full canonical goldens with exact nested order", () => {
    expect(CONVERSATION_FIELD_ORDER).toEqual([
      "id",
      "turn",
      "goal_ref",
      "intent",
      "state",
      "authority_claim",
      "acting_for_claim",
      "reply_by",
      "wake",
      "outcome_code",
      "human_summary",
    ]);
    expect(WAKE_FIELD_ORDER).toEqual(["kind", "floor_seconds"]);
    expect(
      canonicalEnvelopeV3({
        from: FROM,
        to: TO,
        msg_id: MSG_ID,
        message: MESSAGE,
        timestamp: TS,
        expires_at: EXPIRES,
        conversation: MINIMAL_CONVERSATION,
      })
    ).toBe(
      '{"v":3,"from":"zip-grok.smc.viz","to":"viz-grok.smc.viz","msg_id":"msg-v3-golden-00000001","message":"hello mailbox v3","timestamp":"2026-08-25T00:00:00.000Z","expires_at":"2026-08-25T00:10:00.000Z","conversation":{"id":"conv-golden-00000001","turn":1,"goal_ref":"6f8ba9f4601723239f7cb306c09c0367c26cab55a0a8c1ac499b4d31da1c7b41","intent":"propose","state":"proposed"}}'
    );
    expect(
      canonicalEnvelopeV3({
        from: FROM,
        to: TO,
        msg_id: "msg-v3-golden-00000002",
        message: "done",
        timestamp: TS,
        expires_at: EXPIRES,
        reply_to: MSG_ID,
        conversation: FULL_CONVERSATION,
      })
    ).toBe(
      '{"v":3,"from":"zip-grok.smc.viz","to":"viz-grok.smc.viz","msg_id":"msg-v3-golden-00000002","message":"done","timestamp":"2026-08-25T00:00:00.000Z","expires_at":"2026-08-25T00:10:00.000Z","reply_to":"msg-v3-golden-00000001","conversation":{"id":"conv-golden-00000002","turn":7,"goal_ref":"6f8ba9f4601723239f7cb306c09c0367c26cab55a0a8c1ac499b4d31da1c7b41","intent":"complete","state":"completed","authority_claim":"commit","acting_for_claim":"human-owner.smc.viz","reply_by":"2026-08-25T00:05:00.000Z","wake":{"kind":"push","floor_seconds":2},"outcome_code":"goal-achieved","human_summary":"The signed goal is complete."}}'
    );
  });

  it.each(PERMITTED_WIRE_COMBINATIONS)(
    "pins the permitted $intent/$state/$outcome_code canonical wire combination",
    ({ canonical, ...combination }) => {
      const parsed = parseConversationWire({
        ...MINIMAL_CONVERSATION,
        ...combination,
      });
      expect(parsed).toMatchObject(combination);
      expect(
        canonicalEnvelopeV3({
          from: FROM,
          to: TO,
          msg_id: "msg-v3-combo-00000001",
          message: "permitted combination",
          timestamp: TS,
          expires_at: EXPIRES,
          conversation: {
            ...MINIMAL_CONVERSATION,
            ...combination,
          },
        })
      ).toBe(canonical);
    }
  );

  it("rejects unknown fields, vocabularies, unsupported authority, and outcome mismatches", () => {
    const rejected: Array<[Record<string, unknown>, string]> = [
      [{ ...MINIMAL_CONVERSATION, runtime_thread_id: "native-1" }, "E_CONVERSATION_FIELD"],
      [{ ...MINIMAL_CONVERSATION, intent: "approve" }, "E_CONVERSATION_INTENT"],
      [{ ...MINIMAL_CONVERSATION, state: "done" }, "E_CONVERSATION_STATE"],
      [{ ...MINIMAL_CONVERSATION, intent: "accept", state: "proposed" }, "E_CONVERSATION_TRANSITION"],
      [{ ...MINIMAL_CONVERSATION, outcome_code: "goal-achieved" }, "E_CONVERSATION_OUTCOME"],
      [
        { ...MINIMAL_CONVERSATION, intent: "fail", state: "failed" },
        "E_CONVERSATION_OUTCOME",
      ],
      [{ ...MINIMAL_CONVERSATION, authority_claim: "commit-up-to" }, "E_AUTHORITY_UNSUPPORTED"],
      [{ ...MINIMAL_CONVERSATION, authority_claim: "admin" }, "E_CONVERSATION_AUTHORITY"],
      [{ ...MINIMAL_CONVERSATION, wake: { kind: "realtime" } }, "E_CONVERSATION_WAKE"],
      [{ ...MINIMAL_CONVERSATION, wake: { kind: "push", latency_ms: 1 } }, "E_CONVERSATION_FIELD"],
    ];
    for (const [wire, code] of rejected) {
      try {
        parseConversationWire(wire);
        throw new Error("expected conversation rejection");
      } catch (error) {
        expect(error).toBeInstanceOf(ConversationWireError);
        expect((error as ConversationWireError).code).toBe(code);
      }
    }
  });

  it.each(CONVERSATION_AUTHORITY_CLAIMS)(
    "records the optional %s authority claim without enforcing it",
    (authority_claim) => {
      expect(
        parseConversationWire({ ...MINIMAL_CONVERSATION, authority_claim })
      ).toMatchObject({ authority_claim });
    }
  );

  it("enforces shapes, omission-not-null, reply bounds, and the summary byte ceiling", () => {
    const rejected = [
      { ...MINIMAL_CONVERSATION, id: "short" },
      { ...MINIMAL_CONVERSATION, turn: 0 },
      { ...MINIMAL_CONVERSATION, turn: 1.5 },
      { ...MINIMAL_CONVERSATION, goal_ref: GOAL_REF.toUpperCase() },
      { ...MINIMAL_CONVERSATION, authority_claim: null },
      { ...MINIMAL_CONVERSATION, acting_for_claim: "not-a-viz-domain" },
      { ...MINIMAL_CONVERSATION, reply_by: "2026-08-24T23:59:59.999Z" },
      { ...MINIMAL_CONVERSATION, human_summary: "x".repeat(513) },
    ];
    for (const wire of rejected) {
      expect(() => parseConversationWire(wire, TS)).toThrow(ConversationWireError);
    }
    expect(Object.keys(encodeConversationWire(MINIMAL_CONVERSATION))).toEqual([
      "id",
      "turn",
      "goal_ref",
      "intent",
      "state",
    ]);
  });

  it("accepts the fixed protocol turn ceiling and rejects ceiling plus one", () => {
    expect(
      parseConversationWire({
        ...MINIMAL_CONVERSATION,
        turn: AGENT_CONVERSATIONS_PROTOCOL_FIXTURE.max_conversation_turn,
      }).turn
    ).toBe(MAX_CONVERSATION_TURN);
    expect(() =>
      parseConversationWire({
        ...MINIMAL_CONVERSATION,
        turn: AGENT_CONVERSATIONS_PROTOCOL_FIXTURE.max_conversation_turn + 1,
      })
    ).toThrowError(ConversationWireError);
  });

  it.each(WAKE_DERIVATION_VECTORS)("derives wake: $name", ({ input, expected }) => {
    expect(deriveWakeCapability(input)).toEqual(expected);
  });

  it("fails closed on an unknown local wake driver", () => {
    expect(() =>
      deriveWakeCapability({ driver: "native-runtime" } as never)
    ).toThrowError(ConversationWireError);
  });
});

describe("V3 fixed-key signature golden", () => {
  let dir: string;
  let keyPath: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "zipviz-v3-golden-"));
    keyPath = join(dir, "sender.key");
    await mkdir(dir, { recursive: true });
    await writeFile(keyPath, PRIVATE_PEM);
  });

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("matches the deterministic signature and verifies the complete signed block", async () => {
    const signed = await signEnvelopeV3({
      viz_domain: FROM,
      to: TO,
      message: MESSAGE,
      msg_id: MSG_ID,
      timestamp: TS,
      expires_at: EXPIRES,
      conversation: MINIMAL_CONVERSATION,
      key_path: keyPath,
    });
    expect(Buffer.from(signed.signature, "base64").toString("hex")).toBe(
      "db621db8bf81b7c71d7b4719f17e845d97d360713e4de1b0bb415b8f3808daa1548c2742cc8ab3ab4626178bb9a72d199ac83f01b9e97484fdded212450dba09"
    );
    expect(signed.signing_version).toBe(3);
    expect(signed.conversation).toEqual(MINIMAL_CONVERSATION);
    expect(signed).not.toHaveProperty("key_path");

    const cache = new RegistryPubkeyCache({
      fetchFn: async () =>
        new Response(JSON.stringify({ public_key: PUBLIC_HEX }), { status: 200 }),
    });
    await expect(
      verifyEnvelopeV3({
        from: FROM,
        to: TO,
        msg_id: MSG_ID,
        message: MESSAGE,
        timestamp: TS,
        expires_at: EXPIRES,
        conversation: signed.conversation,
        signature: signed.signature,
        now: new Date(TS),
        cache,
      })
    ).resolves.toEqual({ ok: true, pubkeyHex: PUBLIC_HEX });

    const rawPublicKey = Buffer.from(PUBLIC_HEX, "hex");
    expect(
      createPublicKey({
        key: Buffer.concat([
          Buffer.from("302a300506032b6570032100", "hex"),
          rawPublicKey,
        ]),
        format: "der",
        type: "spki",
      }).asymmetricKeyType
    ).toBe("ed25519");
  });

  it("derives signed wake through the shared mapping and rejects direct wake injection", async () => {
    const signed = await signEnvelopeV3({
      viz_domain: FROM,
      to: TO,
      message: "derived wake",
      msg_id: "msg-v3-wake-00000001",
      timestamp: TS,
      expires_at: EXPIRES,
      conversation: MINIMAL_CONVERSATION,
      wake: WAKE_DERIVATION_VECTORS[1].input,
      key_path: keyPath,
    });
    expect(signed.conversation.wake).toEqual(WAKE_DERIVATION_VECTORS[1].expected);

    await expect(
      signEnvelopeV3({
        viz_domain: FROM,
        to: TO,
        message: "injected wake",
        msg_id: "msg-v3-wake-00000002",
        timestamp: TS,
        expires_at: EXPIRES,
        conversation: {
          ...MINIMAL_CONVERSATION,
          wake: { kind: "push" },
        } as never,
        key_path: keyPath,
      })
    ).rejects.toMatchObject({ code: "E_CONVERSATION_WAKE" });
  });

  it("rejects mutation of every signed conversation field", async () => {
    const { wake: _wireWake, ...conversation } = FULL_CONVERSATION;
    const signed = await signEnvelopeV3({
      viz_domain: FROM,
      to: TO,
      message: "all signed fields",
      msg_id: "msg-v3-mutate-fields-01",
      timestamp: TS,
      expires_at: EXPIRES,
      conversation,
      wake: { driver: "webhook", floor_seconds: 2 },
      key_path: keyPath,
    });
    const mutations: ConversationWire[] = [
      { ...signed.conversation, id: "conv-mutated-00000001" },
      { ...signed.conversation, turn: 8 },
      { ...signed.conversation, goal_ref: "f".repeat(64) },
      { ...signed.conversation, intent: "accept" },
      { ...signed.conversation, state: "active" },
      { ...signed.conversation, authority_claim: "propose-only" },
      { ...signed.conversation, acting_for_claim: "other-owner.smc.viz" },
      { ...signed.conversation, reply_by: "2026-08-25T00:06:00.000Z" },
      { ...signed.conversation, wake: { kind: "poll", floor_seconds: 2 } },
      { ...signed.conversation, outcome_code: "cancelled" },
      { ...signed.conversation, human_summary: "Mutated summary." },
    ];
    const cache = new RegistryPubkeyCache({
      fetchFn: async () =>
        new Response(JSON.stringify({ public_key: PUBLIC_HEX }), { status: 200 }),
    });
    for (const mutated of mutations) {
      await expect(
        verifyEnvelopeV3({
          from: FROM,
          to: TO,
          msg_id: signed.msg_id,
          message: "all signed fields",
          timestamp: TS,
          expires_at: EXPIRES,
          conversation: mutated,
          signature: signed.signature,
          now: new Date(TS),
          cache,
        })
      ).rejects.toBeTruthy();
    }
  });
});
