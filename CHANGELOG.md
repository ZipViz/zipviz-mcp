# Changelog

All notable changes to this project are listed here.

## 2.0.0

### Breaking

- `zipviz_send` now always uses recipient-bound V2 envelopes for network sends and rejects legacy
  or unknown network envelope versions before any lookup, signing, or delivery. V1 envelopes are
  no longer accepted for network delivery, so V1-only receivers must upgrade.

### Changed

- Reply acceptance now requires a locally verified V2 receipt bound to the original send. A
  transferable V1 signature no longer authenticates a network reply.
- Fixed-origin registry, verification, and behavior lookups now refuse redirects.
- Protocol admission now requires canonical ISO timestamps, canonical Ed25519 signature encoding,
  valid receipt nonces, and positive signed-envelope lifetimes.
- The final egress-policy hook may complete asynchronously before a connection begins.

## 1.1.1

### Changed

- Tool inputs have size limits, checked before a tool does any work: `.viz` names up to 253
  characters, timestamps up to 64, signatures up to 128, and `zipviz_send` message text up to
  32 KiB of UTF-8. Input over a limit is rejected, never truncated.
- `zipviz_send` refuses a request whose encoded body is over 128 KiB, before anything is sent.
- The stdio transport refuses a single message over 1 MiB.
- Development tooling updated (tsx, esbuild, vite). Runtime dependencies are unchanged.

## 1.1.0

First public source release.

### Tools (stdio)

- `zipviz_lookup`: fetch an agent's public card by `.viz` domain.
- `zipviz_status`: quick identity and trust status check before talking to an agent.
- `zipviz_send`: resolve the recipient's tunnel URL and POST one signed A2A message.
- `zipviz_verify`: verify an Ed25519 signature against the agent's registered public key; the result includes a plain-English explanation.
- `zipviz_sign_message`: sign a message locally with an Ed25519 private key.
- `zipviz_explain_verification`: deprecated; returns no explanation. Use `zipviz_verify`.
