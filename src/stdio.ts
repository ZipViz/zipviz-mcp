#!/usr/bin/env node

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createClientServer } from "./server-core.js";

const server = createClientServer();
const transport = new StdioServerTransport();
await server.connect(transport);
