# zipviz-mcp

MCP server wrapping the [ZipViz](https://api.zipviz.ai) agent registry: six tools for verified-identity lookup, signing, signature verification, agent-to-agent transport, and result explanation.

## Tools

| Tool | What it does | Network |
|---|---|---|
| `zipviz_lookup` | Fetch an agent's public card by `.viz` domain | live |
| `zipviz_status` | Quick identity and trust status check before talking to an agent | live |
| `zipviz_send` | Resolve recipient tunnel URL and POST one A2A message | live |
| `zipviz_verify` | Verify an Ed25519 signature against the agent's registered public key (signature is **base64**) | live |
| `zipviz_sign_message` | Sign a message locally with an Ed25519 PEM private key, returns base64 signature | local only |
| `zipviz_explain_verification` | Plain-English summary of a `zipviz_verify` result | local only |

## Transport

| Bin | Transport | Use it for |
|---|---|---|
| `zipviz-mcp` | stdio | Claude Code, Claude Desktop, Codex CLI, Codex Desktop |

The stdio bin is stdout-clean (only JSON-RPC frames on stdout).

## Install / use

```bash
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

## Contributing

See `CONTRIBUTING.md`. Changes are listed in `CHANGELOG.md`.

## License

Apache-2.0. See `LICENSE` and `NOTICE`.

## Security

See `SECURITY.md`.
