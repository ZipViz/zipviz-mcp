import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerLookup } from "./tools/lookup.js";
import { registerStatus } from "./tools/status.js";
import { registerSend } from "./tools/send.js";
import { registerVerify } from "./tools/verify.js";
import { registerExplainVerification } from "./tools/explain_verification.js";
import { registerSignMessage } from "./tools/sign_message.js";

/**
 * The client tool surface: lookup, status, send, verify, explain_verification
 * and sign_message. `instrument` runs before any tool is registered.
 */
export function createClientServer(opts?: {
  instrument?: (server: McpServer) => void;
}): McpServer {
  const server = new McpServer({
    name: "zipviz-mcp",
    version: "1.1.0",
  });

  opts?.instrument?.(server);

  registerLookup(server);
  registerStatus(server);
  registerSend(server);
  registerVerify(server);
  registerExplainVerification(server);
  registerSignMessage(server);

  return server;
}
