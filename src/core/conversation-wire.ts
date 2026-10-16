import { isValidVizDomain } from "../lib/viz-domain.js";

export type DoorbellDriverName =
  | "none"
  | "webhook"
  | "grok_bot_message"
  | "qm_turns"
  | "signed_webhook";

export const AGENT_CONVERSATIONS_CAPABILITY_URI =
  "https://zipviz.ai/protocols/agent-conversations";
export const AGENT_CONVERSATIONS_ENVELOPE_VERSION = 3 as const;
export const MAX_CONVERSATION_TURN = 2_147_483_647;

export const CONVERSATION_FIELD_ORDER = [
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
] as const;

export const WAKE_FIELD_ORDER = ["kind", "floor_seconds"] as const;

export const CONVERSATION_INTENTS = [
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
] as const;

export const CONVERSATION_STATES = [
  "proposed",
  "active",
  "waiting-human",
  "paused",
  "stalled",
  "completed",
  "failed",
  "closed",
] as const;

export const CONVERSATION_OUTCOME_CODES = [
  "goal-achieved",
  "cancelled",
  "declined",
  "superseded",
  "capability-unavailable",
  "policy-blocked",
  "invalid-request",
  "internal-error",
] as const;

export const CONVERSATION_AUTHORITY_CLAIMS = ["propose-only", "commit"] as const;
export const CONVERSATION_WAKE_KINDS = ["push", "poll", "none"] as const;

export type ConversationIntent = (typeof CONVERSATION_INTENTS)[number];
export type ConversationState = (typeof CONVERSATION_STATES)[number];
export type ConversationOutcomeCode = (typeof CONVERSATION_OUTCOME_CODES)[number];
export type ConversationAuthorityClaim =
  (typeof CONVERSATION_AUTHORITY_CLAIMS)[number];
export type ConversationWakeKind = (typeof CONVERSATION_WAKE_KINDS)[number];

export type ConversationWake = {
  kind: ConversationWakeKind;
  floor_seconds?: number;
};

export type ConversationWire = {
  id: string;
  turn: number;
  goal_ref: string;
  intent: ConversationIntent;
  state: ConversationState;
  authority_claim?: ConversationAuthorityClaim;
  acting_for_claim?: string;
  reply_by?: string;
  wake?: ConversationWake;
  outcome_code?: ConversationOutcomeCode;
  human_summary?: string;
};

export type WakeCapabilityConfig = {
  driver: DoorbellDriverName;
  polling_adapter_configured?: boolean;
  floor_seconds?: number;
};

export class ConversationWireError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "ConversationWireError";
    this.code = code;
  }
}

const CONVERSATION_ID_RE = /^[A-Za-z0-9_-]{8,128}$/;
const GOAL_REF_RE = /^[0-9a-f]{64}$/;
const CONVERSATION_FIELDS = new Set<string>(CONVERSATION_FIELD_ORDER);
const WAKE_FIELDS = new Set<string>(WAKE_FIELD_ORDER);
const INTENTS = new Set<string>(CONVERSATION_INTENTS);
const STATES = new Set<string>(CONVERSATION_STATES);
const OUTCOMES = new Set<string>(CONVERSATION_OUTCOME_CODES);
const AUTHORITY_CLAIMS = new Set<string>(CONVERSATION_AUTHORITY_CLAIMS);
const WAKE_KINDS = new Set<string>(CONVERSATION_WAKE_KINDS);
const DOORBELL_DRIVERS = new Set<string>([
  "none",
  "webhook",
  "grok_bot_message",
  "qm_turns",
  "signed_webhook",
]);

const EXPECTED_STATE: Record<ConversationIntent, ConversationState> = {
  propose: "proposed",
  accept: "active",
  counter: "active",
  ask: "active",
  "needs-human": "waiting-human",
  pause: "paused",
  resume: "active",
  stall: "stalled",
  complete: "completed",
  fail: "failed",
  close: "closed",
};

const OUTCOMES_BY_INTENT: Partial<
  Record<ConversationIntent, ReadonlySet<ConversationOutcomeCode>>
> = {
  complete: new Set(["goal-achieved"]),
  close: new Set(["cancelled", "declined", "superseded"]),
  fail: new Set([
    "capability-unavailable",
    "policy-blocked",
    "invalid-request",
    "internal-error",
  ]),
};

function record(value: unknown, code: string, message: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new ConversationWireError(code, message);
  }
  return value as Record<string, unknown>;
}

function assertKnownFields(
  value: Record<string, unknown>,
  allowed: ReadonlySet<string>
): void {
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) {
      throw new ConversationWireError(
        "E_CONVERSATION_FIELD",
        "conversation contains an unsupported field"
      );
    }
  }
}

function parseWake(value: unknown): ConversationWake {
  const wire = record(value, "E_CONVERSATION_WAKE", "wake must be an object");
  assertKnownFields(wire, WAKE_FIELDS);
  if (typeof wire.kind !== "string" || !WAKE_KINDS.has(wire.kind)) {
    throw new ConversationWireError(
      "E_CONVERSATION_WAKE",
      "wake.kind must be push, poll, or none"
    );
  }
  if (
    wire.floor_seconds !== undefined &&
    (typeof wire.floor_seconds !== "number" ||
      !Number.isSafeInteger(wire.floor_seconds) ||
      wire.floor_seconds < 0)
  ) {
    throw new ConversationWireError(
      "E_CONVERSATION_WAKE",
      "wake.floor_seconds must be a non-negative safe integer"
    );
  }
  return wire.floor_seconds === undefined
    ? { kind: wire.kind as ConversationWakeKind }
    : {
        kind: wire.kind as ConversationWakeKind,
        floor_seconds: wire.floor_seconds as number,
      };
}

export function parseConversationWire(
  value: unknown,
  envelopeTimestamp?: string
): ConversationWire {
  if (value === undefined) {
    throw new ConversationWireError(
      "E_CONVERSATION_MISSING",
      "V3 envelope requires a conversation block"
    );
  }
  const wire = record(
    value,
    "E_CONVERSATION_FIELD",
    "conversation must be an object"
  );
  assertKnownFields(wire, CONVERSATION_FIELDS);

  if (typeof wire.id !== "string" || !CONVERSATION_ID_RE.test(wire.id)) {
    throw new ConversationWireError(
      "E_CONVERSATION_FIELD",
      "conversation.id must be 8-128 characters matching [A-Za-z0-9_-]"
    );
  }
  if (
    typeof wire.turn !== "number" ||
    !Number.isSafeInteger(wire.turn) ||
    wire.turn < 1 ||
    wire.turn > MAX_CONVERSATION_TURN
  ) {
    throw new ConversationWireError(
      "E_CONVERSATION_FIELD",
      `conversation.turn must be an integer from 1 through ${MAX_CONVERSATION_TURN}`
    );
  }
  if (typeof wire.goal_ref !== "string" || !GOAL_REF_RE.test(wire.goal_ref)) {
    throw new ConversationWireError(
      "E_CONVERSATION_FIELD",
      "conversation.goal_ref must be 64 lowercase hexadecimal characters"
    );
  }
  if (typeof wire.intent !== "string" || !INTENTS.has(wire.intent)) {
    throw new ConversationWireError(
      "E_CONVERSATION_INTENT",
      "conversation.intent is not supported"
    );
  }
  if (typeof wire.state !== "string" || !STATES.has(wire.state)) {
    throw new ConversationWireError(
      "E_CONVERSATION_STATE",
      "conversation.state is not supported"
    );
  }

  const intent = wire.intent as ConversationIntent;
  const state = wire.state as ConversationState;
  if (state !== EXPECTED_STATE[intent]) {
    throw new ConversationWireError(
      "E_CONVERSATION_TRANSITION",
      `conversation intent ${intent} requires state ${EXPECTED_STATE[intent]}`
    );
  }

  let authorityClaim: ConversationAuthorityClaim | undefined;
  if (wire.authority_claim !== undefined) {
    if (wire.authority_claim === "commit-up-to") {
      throw new ConversationWireError(
        "E_AUTHORITY_UNSUPPORTED",
        "authority_claim commit-up-to is not supported"
      );
    }
    if (
      typeof wire.authority_claim !== "string" ||
      !AUTHORITY_CLAIMS.has(wire.authority_claim)
    ) {
      throw new ConversationWireError(
        "E_CONVERSATION_AUTHORITY",
        "authority_claim must be propose-only or commit"
      );
    }
    authorityClaim = wire.authority_claim as ConversationAuthorityClaim;
  }

  let actingForClaim: string | undefined;
  if (wire.acting_for_claim !== undefined) {
    if (
      typeof wire.acting_for_claim !== "string" ||
      !isValidVizDomain(wire.acting_for_claim)
    ) {
      throw new ConversationWireError(
        "E_CONVERSATION_AUTHORITY",
        "acting_for_claim must be a valid .viz domain"
      );
    }
    actingForClaim = wire.acting_for_claim;
  }

  let replyBy: string | undefined;
  if (wire.reply_by !== undefined) {
    if (typeof wire.reply_by !== "string" || !Number.isFinite(Date.parse(wire.reply_by))) {
      throw new ConversationWireError(
        "E_CONVERSATION_FIELD",
        "conversation.reply_by must be a valid ISO-8601 timestamp"
      );
    }
    if (
      envelopeTimestamp !== undefined &&
      Number.isFinite(Date.parse(envelopeTimestamp)) &&
      Date.parse(wire.reply_by) < Date.parse(envelopeTimestamp)
    ) {
      throw new ConversationWireError(
        "E_CONVERSATION_FIELD",
        "conversation.reply_by must not be before the envelope timestamp"
      );
    }
    replyBy = wire.reply_by;
  }

  const wake = wire.wake === undefined ? undefined : parseWake(wire.wake);

  let outcomeCode: ConversationOutcomeCode | undefined;
  const permittedOutcomes = OUTCOMES_BY_INTENT[intent];
  if (permittedOutcomes) {
    if (
      typeof wire.outcome_code !== "string" ||
      !OUTCOMES.has(wire.outcome_code) ||
      !permittedOutcomes.has(wire.outcome_code as ConversationOutcomeCode)
    ) {
      throw new ConversationWireError(
        "E_CONVERSATION_OUTCOME",
        `conversation.outcome_code is required and invalid for ${intent}`
      );
    }
    outcomeCode = wire.outcome_code as ConversationOutcomeCode;
  } else if (wire.outcome_code !== undefined) {
    throw new ConversationWireError(
      "E_CONVERSATION_OUTCOME",
      `conversation.outcome_code is prohibited for ${intent}`
    );
  }

  let humanSummary: string | undefined;
  if (wire.human_summary !== undefined) {
    if (
      typeof wire.human_summary !== "string" ||
      Buffer.byteLength(wire.human_summary, "utf8") > 512
    ) {
      throw new ConversationWireError(
        "E_CONVERSATION_FIELD",
        "conversation.human_summary must be at most 512 UTF-8 bytes"
      );
    }
    humanSummary = wire.human_summary;
  }

  const parsed: ConversationWire = {
    id: wire.id,
    turn: wire.turn,
    goal_ref: wire.goal_ref,
    intent,
    state,
  };
  if (authorityClaim !== undefined) parsed.authority_claim = authorityClaim;
  if (actingForClaim !== undefined) parsed.acting_for_claim = actingForClaim;
  if (replyBy !== undefined) parsed.reply_by = replyBy;
  if (wake !== undefined) parsed.wake = wake;
  if (outcomeCode !== undefined) parsed.outcome_code = outcomeCode;
  if (humanSummary !== undefined) parsed.human_summary = humanSummary;
  return parsed;
}

export function encodeConversationWire(
  value: unknown,
  envelopeTimestamp?: string
): ConversationWire {
  const wire = parseConversationWire(value, envelopeTimestamp);
  const encoded: ConversationWire = {
    id: wire.id,
    turn: wire.turn,
    goal_ref: wire.goal_ref,
    intent: wire.intent,
    state: wire.state,
  };
  if (wire.authority_claim !== undefined) {
    encoded.authority_claim = wire.authority_claim;
  }
  if (wire.acting_for_claim !== undefined) {
    encoded.acting_for_claim = wire.acting_for_claim;
  }
  if (wire.reply_by !== undefined) encoded.reply_by = wire.reply_by;
  if (wire.wake !== undefined) {
    encoded.wake =
      wire.wake.floor_seconds === undefined
        ? { kind: wire.wake.kind }
        : { kind: wire.wake.kind, floor_seconds: wire.wake.floor_seconds };
  }
  if (wire.outcome_code !== undefined) encoded.outcome_code = wire.outcome_code;
  if (wire.human_summary !== undefined) encoded.human_summary = wire.human_summary;
  return encoded;
}

export function deriveWakeCapability(config: WakeCapabilityConfig): ConversationWake {
  if (!DOORBELL_DRIVERS.has(config.driver)) {
    throw new ConversationWireError(
      "E_CONVERSATION_WAKE",
      "wake driver is not supported"
    );
  }
  if (
    config.floor_seconds !== undefined &&
    (!Number.isSafeInteger(config.floor_seconds) || config.floor_seconds < 0)
  ) {
    throw new ConversationWireError(
      "E_CONVERSATION_WAKE",
      "wake floor_seconds must be a non-negative safe integer"
    );
  }

  const kind: ConversationWakeKind =
    config.driver === "signed_webhook" ||
    config.driver === "qm_turns" ||
    config.driver === "webhook"
      ? "push"
      : config.polling_adapter_configured === true
        ? "poll"
        : "none";

  if (kind === "none" || config.floor_seconds === undefined) return { kind };
  return { kind, floor_seconds: config.floor_seconds };
}
