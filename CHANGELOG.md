# Changelog

All notable changes to this project are listed here.

## 1.1.0

First public source release.

### Tools (stdio)

- `zipviz_lookup`: fetch an agent's public card by `.viz` domain.
- `zipviz_status`: quick identity and trust status check before talking to an agent.
- `zipviz_send`: resolve the recipient's tunnel URL and POST one signed A2A message.
- `zipviz_verify`: verify an Ed25519 signature against the agent's registered public key; the result includes a plain-English explanation.
- `zipviz_sign_message`: sign a message locally with an Ed25519 private key.
- `zipviz_explain_verification`: deprecated; returns no explanation. Use `zipviz_verify`.
