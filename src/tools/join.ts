import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { JoinClient, JoinError, JOIN_MESSAGES, joinStartSchema, joinStatusSchema, joinResumeSchema } from "../lib/join-client.js";

/** Local stdio registration only; no caller-selected paths, server origins or grants. */
export function registerJoinTools(server: McpServer, client = new JoinClient()): void {
  const output = async (operation: () => Promise<unknown>) => {
    try { return { content: [{ type: "text" as const, text: JSON.stringify(await operation()) }] }; }
    catch (error) {
      const code = (error as { code?: unknown })?.code;
      const safeCode = typeof code === "string" && Object.hasOwn(JOIN_MESSAGES, code) ? code : "E_JOIN_STORE";
      return { isError: true, content: [{ type: "text" as const, text: JSON.stringify({ code: safeCode,
        error: JOIN_MESSAGES[safeCode], ...(error instanceof JoinError && error.signupId ? { signup_id: error.signupId } : {}),
        ...(error instanceof JoinError && error.retryAfter ? { retry_after_s: error.retryAfter } : {}) }) }] };
    }
  };
  // Use strict object schemas at the MCP boundary; the start union is checked
  // inside the handler so tools/list remains an object schema for MCP clients.
  server.registerTool("zipviz_join_start", {
    description: "Prepare a local Ed25519 join request and return the human approval URL, code and key fingerprint. Give all three to your human. To resume, pass only signup_id; the exact private attempts are retained. Does not approve, enroll grants or send messages.",
    inputSchema: z.object({ name: z.string().optional(), owner_email: z.string().optional(),
      runtime: z.string().optional(), introduced_by: z.string().nullable().optional(), signup_id: z.string().optional() }).strict(),
  }, async args => output(async () => {
    const parsed = joinStartSchema.safeParse(args);
    if (!parsed.success) throw new JoinError("E_JOIN_INPUT");
    return client.start(parsed.data);
  }));
  server.registerTool("zipviz_join_status", {
    description: "Poll a signup. Never reads or moves keys and never adopts. Optional wait honors the registry interval and slow-down; returns after a terminal state or ten polls.",
    inputSchema: joinStatusSchema,
  }, async args => output(() => client.status(args)));
  server.registerTool("zipviz_join_cancel", {
    description: "Cancel a pending signup with its local key. Retains local key and attempts; does not revoke a live identity.",
    inputSchema: joinResumeSchema,
  }, async ({ signup_id }) => output(() => client.cancel(signup_id)));
  server.registerTool("zipviz_join_adopt", {
    description: "Explicitly adopt a locally prepared, approved signup after checking its current registered active key, final domain and incarnation. Never replaces an existing key or changes bots.json grants.",
    inputSchema: joinResumeSchema,
  }, async ({ signup_id }) => output(() => client.adopt(signup_id)));
}
