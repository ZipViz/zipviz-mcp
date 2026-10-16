import { z } from "zod";
import { sharedBehaviourLookup } from "../core/behaviour.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { zipvizFetch } from "../lib/api.js";
import type { AgentCard } from "../lib/types.js";
import { cardName, cardTokens, wrapCardFreeText } from "../lib/registry-card.js";
import { boundModelText } from "../lib/model-text.js";

export function registerStatus(server: McpServer) {
  server.registerTool(
    "zipviz_status",
    {
      description:
        "Check if an agent on the ZipViz network is verified and holds trust status. Use this for quick trust checks before communicating with an agent.",
      inputSchema: {
        domain: z
          .string()
          .describe("The agent domain to check, e.g. ticki.adkgo.viz"),
      },
    },
    async ({ domain }) => {
      const card = await zipvizFetch<AgentCard>(
        `/v1/agent/${encodeURIComponent(domain)}/card`
      );

      // The card omits blue_tick entirely when the registry holds no behavioural
      // measurement, and `?? false` turned that absence into a definite "no
      // tick" — reporting an unmeasured agent as one that failed. Different
      // answers, and a caller cannot tell them apart afterwards.
      //
      // Detail comes from the same source every other surface reads, so status,
      // the claim block and the send attestation cannot disagree.
      // The process-wide lookup, shared with the send attestation: two tool
      // calls for the same agent in one burst cost one request, and an endpoint
      // that is throttling answers `unknown` at once instead of costing every
      // caller a 2.5 s wait. A success is never cached, so a drift flip is still
      // visible on the next call.
      const behaviour = await sharedBehaviourLookup().get(domain);
      const name = cardName(card);
      const status = {
        domain: name ?? domain,
        name,
        blueTick: behaviour ? behaviour.blue_tick : (card.blue_tick ?? "unknown"),
        protocols: cardTokens(card.protocols),
        ...(behaviour ? { behaviour } : {}),
      };

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(status, null, 2),
          },
          ...(name === undefined && typeof card.name === "string" && card.name.length > 0
            ? [{ type: "text" as const, text: wrapCardFreeText(domain, { name: boundModelText(card.name, 253, true) }) }]
            : []),
        ],
      };
    }
  );
}
