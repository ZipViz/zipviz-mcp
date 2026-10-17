# zipviz-mcp

MCP server wrapping the [ZipViz](https://api.zipviz.ai) agent registry: tools for verified-identity lookup, signing, signature verification and agent-to-agent transport.

Published on npm as [`zipviz-mcp`](https://www.npmjs.com/package/zipviz-mcp).

## Quickstart

Requires Node.js 22.13 or later. Each client starts the server with `npx`, so there is nothing to
install first.

**Claude Code:**

```sh
claude mcp add zipviz -- npx -y zipviz-mcp
```

**Claude Desktop:** add this to `claude_desktop_config.json` (Settings → Developer → Edit Config),
then restart Claude Desktop.

**Cursor:** add the same block to `~/.cursor/mcp.json` (all projects) or `.cursor/mcp.json` (one
project).

```json
{
  "mcpServers": {
    "zipviz": {
      "command": "npx",
      "args": ["-y", "zipviz-mcp"]
    }
  }
}
```

**First call:** ask your assistant to "use zipviz_lookup to look up zorro-her.smc.viz". The tool
returns the agent card as JSON: name, tunnel URL, Ed25519 public key, protocols and
authentication schemes. Any text the registrant wrote comes back in a separate block labelled
untrusted.

To sign messages with `zipviz_sign_message`, create a key with the
[zipviz CLI](https://github.com/ZipViz/zipviz-cli) first (`npm install -g zipviz`, then
`zipviz keygen`). Both use `~/.zipviz/keys/`.

## Tools

| Tool | What it does | Network |
|---|---|---|
| `zipviz_lookup` | Fetch an agent's public card by `.viz` domain | live |
| `zipviz_status` | Quick identity and trust status check before talking to an agent | live |
| `zipviz_send` | Resolve recipient tunnel URL and POST one A2A message | live |
| `zipviz_verify` | Verify an Ed25519 signature against the agent's registered public key (signature is **base64**); the result includes a plain-English explanation | live |
| `zipviz_sign_message` | Sign a message locally with an Ed25519 PEM private key, returns base64 signature | local only |
| `zipviz_explain_verification` | Deprecated. Returns no explanation; use `zipviz_verify`, which includes one | local only |

## Transport

| Bin | Transport | Use it for |
|---|---|---|
| `zipviz-mcp` | stdio | Claude Code, Claude Desktop, Cursor, Codex CLI, Codex Desktop |

The stdio bin is stdout-clean (only JSON-RPC frames on stdout).

## Development

```bash
git clone https://github.com/ZipViz/zipviz-mcp && cd zipviz-mcp
npm ci
npm run build              # produces dist/stdio.js
npm test                   # vitest
```

Local dev without building:

```bash
npm run dev                # stdio
```

## API surface

All tools call `https://api.zipviz.ai`. See `src/lib/types.ts` for the response shapes (`AgentCard`, `VerifyResponse`, `A2AResponse`).

## Security notes

- Private keys for `zipviz_sign_message` default to `~/.zipviz/keys/<viz_domain>.key` and never leave the local machine. `key_path` is **rejected** and `viz_domain` must match a strict `.viz` regex, so the tool cannot act as a signing oracle for arbitrary local keys.
- `zipviz_send` is intentionally a thin transport helper: no queues, retries, scheduling, or routing logic.

## Related

- [zipviz-cli](https://github.com/ZipViz/zipviz-cli): create a key, claim a name, and verify names and signatures from the command line.
- [zipviz-openapi](https://github.com/ZipViz/zipviz-openapi): the OpenAPI specification of the public registry API.
- [zipviz.ai/developers](https://zipviz.ai/developers)

## Contributing

See `CONTRIBUTING.md`. Changes are listed in `CHANGELOG.md`.

## License

Apache-2.0. See `LICENSE` and `NOTICE`.

## Security

See `SECURITY.md`.
