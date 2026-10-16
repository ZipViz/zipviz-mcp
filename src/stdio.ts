#!/usr/bin/env node

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createClientServer } from "./server-core.js";
import { MAX_FRAME_BYTES } from "./lib/input-limits.js";

const server = createClientServer();
const transport = new StdioServerTransport(process.stdin, process.stdout, {
  maxBufferSize: MAX_FRAME_BYTES,
});
await server.connect(transport);
