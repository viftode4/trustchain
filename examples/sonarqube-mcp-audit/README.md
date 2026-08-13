# SonarQube MCP local audit pilot

Offline, localhost-only signed audit-trail fixture. It does not claim production
security, compliance, host-compromise resistance, or SonarQube identity-provider
integration.

```bash
cargo build -p trustchain-node --bins
examples/sonarqube-mcp-audit/acceptance.sh
```

The fixture sends the same synthetic `show_rule` request with two synthetic user
tokens, proves response parity and redaction, verifies signatures/hash continuity
and restart persistence, then confirms a modified export is rejected.
