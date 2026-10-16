import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { zipvizFetch } from "../lib/api.js";
import type { AgentCard } from "../lib/types.js";
import { cardFreeText, cardName, cardTokens, wrapCardFreeText } from "../lib/registry-card.js";

export function registerLookup(server: McpServer) {
  server.registerTool(
    "zipviz_lookup",
    {
      description:
        "Look up an agent on the ZipViz network by domain. Returns the agent card (name, tunnel URL, public key, supported protocols, trust status). Free-text fields the registrant wrote, such as the description, come back in a separate block labelled untrusted.",
      inputSchema: {
        domain: z
          .string()
          .describe("The agent domain to look up, e.g. ticki.adkgo.viz"),
      },
    },
    async ({ domain }) => {
      const card = await zipvizFetch<AgentCard>(
        `/v1/agent/${encodeURIComponent(domain)}/card`
      );

      const structured = {
        name: cardName(card),
        url: typeof card.url === "string" ? card.url : undefined,
        public_key: card.public_key,
        protocols: cardTokens(card.protocols),
        authentication: { schemes: cardTokens(card.authentication?.schemes) },
        created: typeof card.created === "string" ? card.created.slice(0, 64) : undefined,
        ...(card.blue_tick !== undefined ? { blue_tick: card.blue_tick } : {}),
      };
      const freeText = cardFreeText(card);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(structured, null, 2),
          },
          ...(freeText
            ? [{ type: "text" as const, text: wrapCardFreeText(domain, freeText) }]
            : []),
        ],
      };
    }
  );
}
