# GitHub Copilot Instructions for AIP

This document provides context for GitHub Copilot when working on the Agent Identity Protocol codebase.

## Project Overview

AIP (Agent Identity Protocol) is a **zero-trust security layer for AI agents**. It provides:

1. **Policy Enforcement Proxy**: Intercepts MCP (Model Context Protocol) tool calls
2. **Manifest-Driven Security**: Declarative YAML policies define what agents can do
3. **Human-in-the-Loop**: Native OS prompts for sensitive operations
4. **DLP (Data Loss Prevention)**: Redacts sensitive data in tool responses
5. **Audit Logging**: Immutable JSONL logs for compliance

## Architecture

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  MCP Client │────▶│    AIP Proxy     │────▶│   MCP Server    │
│   (Agent)   │◀────│  Policy Engine   │◀────│  (Subprocess)   │
└─────────────┘     └──────────────────┘     └─────────────────┘
```

The proxy is a **stdin/stdout passthrough** that:
- Reads JSON-RPC from stdin (client requests)
- Checks `tools/call` requests against policy
- Forwards allowed requests to subprocess
- Returns errors for blocked requests
- Scans responses for sensitive data (DLP)
- Logs all decisions to audit file

## Code Style

### Go Guidelines

- **Format**: Always run `gofmt -s -w .`
- **Imports**: Standard library first, then external, then internal
- **Errors**: Wrap with context using `fmt.Errorf("context: %w", err)`
- **Logging**: 
  - `logger` (stderr) for operational logs
  - `auditLogger` (file) for audit trail
  - **NEVER** write to stdout except JSON-RPC responses

### Critical Constraints

1. **stdout is sacred**: Only JSON-RPC messages go to stdout
2. **Fail-closed**: Unknown operations = deny
3. **Zero-trust**: Every tool call is checked, no implicit permissions

## Key Files

| Path | Purpose |
|------|---------|
| `proxy/cmd/aip-proxy/main.go` | Entry point, proxy logic |
| `proxy/pkg/policy/engine.go` | Policy loading and evaluation |
| `proxy/pkg/dlp/scanner.go` | DLP regex scanning |
| `proxy/pkg/audit/logger.go` | JSONL audit logging |
| `proxy/pkg/ui/prompt.go` | Native OS dialogs |
| `proxy/pkg/protocol/types.go` | JSON-RPC types |

## Common Tasks

### Adding a New Policy Feature

1. Update `proxy/pkg/policy/engine.go` with new evaluation logic
2. Update policy types in the same file
3. Add tests in `engine_test.go`
4. Update example policies in `proxy/examples/`
5. Document in README or docs/

### Adding a New CLI Flag

1. Add flag definition in `parseFlags()` in `main.go`
2. Update usage message
3. Add handling logic
4. Update README with new flag

### Adding DLP Pattern

1. Patterns are defined in policy YAML under `spec.dlp.patterns`
2. Test regex in `dlp/scanner_test.go`
3. Add example to `proxy/examples/agent.yaml`

## Testing

```bash
cd proxy
make test          # Run all tests
make lint          # Lint checks
make build         # Build binary
make run-demo      # Test with echo server
```

## Policy YAML Structure

```yaml
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: policy-name
spec:
  mode: enforce | monitor
  allowed_tools:
    - tool_name
  tool_rules:
    - tool: tool_name
      action: allow | block | ask
      allow_args:
        arg_name: "regex_pattern"
  dlp:
    patterns:
      - name: "Pattern Name"
        regex: "pattern"
```

## Security Considerations

When writing code for AIP:

1. **Input Validation**: Always validate policy YAML fields
2. **Regex Safety**: Use timeouts for regex evaluation (DoS prevention)
3. **Memory Safety**: Don't hold sensitive data longer than needed
4. **Audit Trail**: Log security-relevant decisions
5. **Error Messages**: Don't leak internal paths or secrets

## MCP Protocol

AIP speaks JSON-RPC over stdio. Key methods:

- `tools/call` - Agent invokes a tool (intercepted by AIP)
- `tools/list` - List available tools (passthrough)
- Other methods - Passed through without policy check
