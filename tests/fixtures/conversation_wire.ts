import type {
  ConversationWire,
  WakeCapabilityConfig,
} from "../../src/core/conversation-wire.js";

export const AGENT_CONVERSATIONS_PROTOCOL_FIXTURE = {
  capability_family_uri: "https://zipviz.ai/protocols/agent-conversations",
  envelope_version: 3,
  max_conversation_turn: 2_147_483_647,
} as const;

export const GOAL_REF =
  "6f8ba9f4601723239f7cb306c09c0367c26cab55a0a8c1ac499b4d31da1c7b41";

export const MINIMAL_CONVERSATION: ConversationWire = {
  id: "conv-golden-00000001",
  turn: 1,
  goal_ref: GOAL_REF,
  intent: "propose",
  state: "proposed",
};

export const FULL_CONVERSATION: ConversationWire = {
  id: "conv-golden-00000002",
  turn: 7,
  goal_ref: GOAL_REF,
  intent: "complete",
  state: "completed",
  authority_claim: "commit",
  acting_for_claim: "human-owner.smc.viz",
  reply_by: "2026-08-25T00:05:00.000Z",
  wake: { kind: "push", floor_seconds: 2 },
  outcome_code: "goal-achieved",
  human_summary: "The signed goal is complete.",
};

const COMBINATION_ENVELOPE_PREFIX =
  '{"v":3,"from":"zip-grok.smc.viz","to":"viz-grok.smc.viz","msg_id":"msg-v3-combo-00000001","message":"permitted combination","timestamp":"2026-08-25T00:00:00.000Z","expires_at":"2026-08-25T00:10:00.000Z","conversation":';
const COMBINATION_CONVERSATION_PREFIX =
  '{"id":"conv-golden-00000001","turn":1,"goal_ref":"6f8ba9f4601723239f7cb306c09c0367c26cab55a0a8c1ac499b4d31da1c7b41"';

function combinationGolden(orderedFields: string): string {
  return `${COMBINATION_ENVELOPE_PREFIX}${COMBINATION_CONVERSATION_PREFIX}${orderedFields}` + "}";
}

export const PERMITTED_WIRE_COMBINATIONS = [
  {
    intent: "propose",
    state: "proposed",
    canonical: combinationGolden(',"intent":"propose","state":"proposed"}'),
  },
  {
    intent: "accept",
    state: "active",
    canonical: combinationGolden(',"intent":"accept","state":"active"}'),
  },
  {
    intent: "counter",
    state: "active",
    canonical: combinationGolden(',"intent":"counter","state":"active"}'),
  },
  {
    intent: "ask",
    state: "active",
    canonical: combinationGolden(',"intent":"ask","state":"active"}'),
  },
  {
    intent: "needs-human",
    state: "waiting-human",
    canonical: combinationGolden(
      ',"intent":"needs-human","state":"waiting-human"}'
    ),
  },
  {
    intent: "pause",
    state: "paused",
    canonical: combinationGolden(',"intent":"pause","state":"paused"}'),
  },
  {
    intent: "resume",
    state: "active",
    canonical: combinationGolden(',"intent":"resume","state":"active"}'),
  },
  {
    intent: "stall",
    state: "stalled",
    canonical: combinationGolden(',"intent":"stall","state":"stalled"}'),
  },
  {
    intent: "complete",
    state: "completed",
    outcome_code: "goal-achieved",
    canonical: combinationGolden(
      ',"intent":"complete","state":"completed","outcome_code":"goal-achieved"}'
    ),
  },
  {
    intent: "close",
    state: "closed",
    outcome_code: "cancelled",
    canonical: combinationGolden(
      ',"intent":"close","state":"closed","outcome_code":"cancelled"}'
    ),
  },
  {
    intent: "close",
    state: "closed",
    outcome_code: "declined",
    canonical: combinationGolden(
      ',"intent":"close","state":"closed","outcome_code":"declined"}'
    ),
  },
  {
    intent: "close",
    state: "closed",
    outcome_code: "superseded",
    canonical: combinationGolden(
      ',"intent":"close","state":"closed","outcome_code":"superseded"}'
    ),
  },
  {
    intent: "fail",
    state: "failed",
    outcome_code: "capability-unavailable",
    canonical: combinationGolden(
      ',"intent":"fail","state":"failed","outcome_code":"capability-unavailable"}'
    ),
  },
  {
    intent: "fail",
    state: "failed",
    outcome_code: "policy-blocked",
    canonical: combinationGolden(
      ',"intent":"fail","state":"failed","outcome_code":"policy-blocked"}'
    ),
  },
  {
    intent: "fail",
    state: "failed",
    outcome_code: "invalid-request",
    canonical: combinationGolden(
      ',"intent":"fail","state":"failed","outcome_code":"invalid-request"}'
    ),
  },
  {
    intent: "fail",
    state: "failed",
    outcome_code: "internal-error",
    canonical: combinationGolden(
      ',"intent":"fail","state":"failed","outcome_code":"internal-error"}'
    ),
  },
] as const;

export const WAKE_DERIVATION_VECTORS: ReadonlyArray<{
  name: string;
  input: WakeCapabilityConfig;
  expected: ConversationWire["wake"];
}> = [
  {
    name: "validated signed webhook pushes without an invented floor",
    input: { driver: "signed_webhook" },
    expected: { kind: "push" },
  },
  {
    name: "qm turns carries only its explicit floor",
    input: { driver: "qm_turns", floor_seconds: 3 },
    expected: { kind: "push", floor_seconds: 3 },
  },
  {
    name: "ordinary webhook is a push path",
    input: { driver: "webhook" },
    expected: { kind: "push" },
  },
  {
    name: "permanently unavailable grok driver falls back to configured polling",
    input: { driver: "grok_bot_message", polling_adapter_configured: true },
    expected: { kind: "poll" },
  },
  {
    name: "permanently unavailable grok driver advertises none without polling",
    input: { driver: "grok_bot_message" },
    expected: { kind: "none" },
  },
  {
    name: "driver none can advertise configured polling with an explicit floor",
    input: {
      driver: "none",
      polling_adapter_configured: true,
      floor_seconds: 30,
    },
    expected: { kind: "poll", floor_seconds: 30 },
  },
  {
    name: "no push and no polling advertises none",
    input: { driver: "none" },
    expected: { kind: "none" },
  },
];
