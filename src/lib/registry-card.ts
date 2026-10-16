import type { AgentCard } from "./types.js";
import { boundModelText } from "./model-text.js";
import { wrapUntrusted } from "./untrusted.js";
import { isValidVizDomain } from "./viz-domain.js";

// Registry card text is written by whoever registered the agent. Only values
// with a fixed, checkable shape stay in the structured result; free text goes
// into a bounded block labelled as untrusted.
const MAX_DESCRIPTION = 1024;
const MAX_TOKEN = 64;
const MAX_LIST = 32;
const TOKEN_RE = /^[A-Za-z0-9._:-]{1,64}$/;

export function cardTokens(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((v): v is string => typeof v === "string" && TOKEN_RE.test(v)).slice(0, MAX_LIST);
}

export function cardName(card: AgentCard): string | undefined {
  return isValidVizDomain(card.name) ? card.name : undefined;
}

// Free-text card fields, bounded, or undefined when there are none.
export function cardFreeText(card: AgentCard): Record<string, unknown> | undefined {
  const text: Record<string, unknown> = {};
  if (cardName(card) === undefined && typeof card.name === "string" && card.name.length > 0) {
    text.name = boundModelText(card.name, 253, true);
  }
  const description = boundModelText(card.description, MAX_DESCRIPTION, true);
  if (description) text.description = description;
  if (Array.isArray(card.capabilities)) {
    const capabilities = card.capabilities
      .slice(0, MAX_LIST)
      .map((c) => boundModelText(c, MAX_TOKEN, true))
      .filter((c) => c.length > 0);
    if (capabilities.length > 0) text.capabilities = capabilities;
  }
  return Object.keys(text).length > 0 ? text : undefined;
}

export function wrapCardFreeText(domain: string, text: Record<string, unknown>): string {
  return wrapUntrusted(domain, "Registry card text written by the agent's registrant:\n" + JSON.stringify(text, null, 2));
}
