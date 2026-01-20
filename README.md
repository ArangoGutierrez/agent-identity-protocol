# Agent Identity Protocol (AIP)

**"Sudo for AI Agents" — The Zero-Trust Security Layer for Autonomous Agents**

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Security Policy](https://img.shields.io/badge/Security-Policy-red.svg)](SECURITY.md)
[![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8?logo=go)](https://go.dev/)
[![CI](https://github.com/ArangoGutierrez/agent-identity-protocol/actions/workflows/ci.yml/badge.svg)](https://github.com/ArangoGutierrez/agent-identity-protocol/actions/workflows/ci.yml)
[![Status](https://img.shields.io/badge/Status-Alpha-orange.svg)]()

---

## The Problem: God Mode by Default

Modern AI agents operate with **unrestricted access** to powerful tools. When you grant an LLM access to your GitHub account, database, or cloud infrastructure, you're not just giving it an API key—you're granting **unbounded intent execution** with no policy layer.

### The Threat Model

| Threat | Description | Real-World Example |
|--------|-------------|-------------------|
| **Indirect Prompt Injection** | Malicious instructions embedded in data the agent processes | *GeminiJack* (2024): Attackers embedded prompts in Google Docs that hijacked Gemini's actions |
| **Consent Fatigue** | Users approve broad permissions without understanding scope | "Allow GitHub access" grants `repo:delete`, not just `repo:read` |
| **Shadow AI** | Agents operating outside enterprise security boundaries | Developers running local Copilot instances with production credentials |
| **Privilege Escalation** | Agents accumulating permissions across tool calls | Agent chains: Slack → Calendar → Email → sends unauthorized messages |
| **Data Exfiltration** | Sensitive data leaving through unmonitored egress | Agent "summarizing" code by posting to external APIs |

### API Keys Are for Code. AIP Is for Intent.

Traditional security assumes **deterministic code execution**. API keys authenticate the *application*. But LLMs are non-deterministic systems executing *user intent* through *model interpretation*.

```
Traditional: Code → API Key → Resource
    └── Deterministic, auditable, predictable

Agent World: User Intent → LLM Interpretation → Tool Call → Resource
    └── Non-deterministic, opaque, emergent behavior
```

**We need a security primitive that authenticates and authorizes *intent*, not just identity.**

---

## The Solution: Manifest-Driven Security Layer

AIP introduces a **policy enforcement proxy** that sits between your agent and the outside world. Every tool call is validated against a declarative manifest before execution.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          TRUST BOUNDARY                                      │
│  ┌──────────┐    ┌─────────────────┐    ┌──────────────┐    ┌────────────┐ │
│  │          │    │                 │    │              │    │            │ │
│  │  Agent   │───▶│   AIP Proxy     │───▶│ Policy Check │───▶│ Real Tool  │ │
│  │  (LLM)   │    │   (Sidecar)     │    │ (agent.yaml) │    │ (GitHub)   │ │
│  │          │◀───│                 │◀───│              │◀───│            │ │
│  └──────────┘    └─────────────────┘    └──────────────┘    └────────────┘ │
│                         │                      │                            │
│                         ▼                      ▼                            │
│                  ┌─────────────┐       ┌──────────────┐                    │
│                  │ Audit Log   │       │ Identity     │                    │
│                  │ (immutable) │       │ Federation   │                    │
│                  └─────────────┘       └──────────────┘                    │
└─────────────────────────────────────────────────────────────────────────────┘
```

```mermaid
flowchart LR
    subgraph Agent["Agent Runtime"]
        LLM[LLM/Agent]
    end
    
    subgraph AIP["AIP Proxy Sidecar"]
        Proxy[Proxy]
        Policy[Policy Engine]
        Manifest[(agent.yaml)]
        Audit[Audit Log]
    end
    
    subgraph Tools["External Tools"]
        GitHub[GitHub API]
        Postgres[(PostgreSQL)]
        Slack[Slack API]
    end
    
    LLM -->|Tool Call| Proxy
    Proxy --> Policy
    Policy --> Manifest
    Policy -->|ALLOW| GitHub
    Policy -->|ALLOW| Postgres
    Policy -->|DENY| Slack
    Policy --> Audit
    
    style Policy fill:#f9f,stroke:#333
    style Manifest fill:#bbf,stroke:#333
```

---

## Core Concepts

### 1. The Manifest (`agent.yaml`)

Every agent declares its **capabilities and constraints** in a manifest. This is the single source of truth for what an agent *should* be able to do.

```yaml
# agent.yaml - Declarative policy for a code review agent
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: code-review-agent
  version: 1.0.0
  owner: platform-team@company.com

spec:
  # Identity assertion method
  identity:
    provider: oidc
    issuer: https://auth.company.com
    audience: aip-proxy
    
  # Capability declarations (what the agent CAN request)
  capabilities:
    - name: github
      operations:
        - action: repos.get
          scope: "org:mycompany/*"
        - action: pulls.list
          scope: "org:mycompany/*"
        - action: pulls.createReview
          scope: "org:mycompany/*"
          constraints:
            event: ["COMMENT", "APPROVE"]  # Cannot REQUEST_CHANGES
        # Explicitly DENY destructive operations
        - action: repos.delete
          effect: deny
        - action: git.push
          effect: deny
          
    - name: postgres
      operations:
        - action: query
          constraints:
            tables: ["pull_requests", "reviews"]
            operations: ["SELECT"]  # Read-only
            
  # Egress filtering
  egress:
    allowlist:
      - "api.github.com"
      - "postgres.internal.company.com:5432"
    denylist:
      - "*"  # Default deny all other egress
      
  # Rate limiting
  limits:
    requests_per_minute: 100
    max_tokens_per_request: 4096
    
  # Session constraints
  session:
    max_duration: 1h
    require_human_approval:
      - pattern: "*.delete"
      - pattern: "*.push"
```

### 2. Identity Federation

AIP replaces **static, long-lived API keys** with **short-lived, scoped identity assertions**.

| Traditional | AIP |
|------------|-----|
| API key embedded in agent code | OIDC token issued per session |
| Key valid indefinitely | Token expires in minutes |
| Full API access | Scoped to manifest capabilities |
| Shared across environments | Unique per agent instance |
| Revocation = rotate everywhere | Revocation = deny at proxy |

**Identity Chain:**

```
Human User (authenticated)
    └─▶ Spawns Agent Session (scoped)
            └─▶ Agent receives short-lived AIP token
                    └─▶ Token encodes: user_id, agent_id, manifest_hash, exp
                            └─▶ Proxy validates token + manifest on every call
```

### 3. Egress Filtering & Data Loss Prevention

Agents should only communicate with **declared endpoints**. AIP enforces network-level egress controls:

```yaml
egress:
  allowlist:
    - "api.github.com"           # Explicit GitHub access
    - "*.internal.company.com"   # Internal services only
  denylist:
    - "pastebin.com"             # Known exfil targets
    - "*.ngrok.io"
    - "*"                        # Default deny
    
  # Content inspection
  dlp:
    block_patterns:
      - "(?i)api[_-]?key"
      - "(?i)secret"
      - "-----BEGIN .* PRIVATE KEY-----"
```

### 4. Audit & Observability

Every tool call is logged with full context for forensic analysis:

```json
{
  "timestamp": "2026-01-20T14:32:01Z",
  "session_id": "aip-session-7f3d2a1b",
  "agent_id": "code-review-agent",
  "user_id": "alice@company.com",
  "tool_call": {
    "tool": "github",
    "action": "pulls.createReview",
    "parameters": {
      "owner": "mycompany",
      "repo": "backend",
      "pull_number": 1234,
      "event": "APPROVE"
    }
  },
  "policy_decision": "ALLOW",
  "manifest_version": "1.0.0",
  "manifest_hash": "sha256:a1b2c3...",
  "latency_ms": 45
}
```

---

## Security Comparison

| Aspect | Standard MCP | AIP-Enabled MCP |
|--------|--------------|-----------------|
| **Authentication** | Static API keys | Short-lived OIDC tokens |
| **Authorization** | None (full access) | Per-action policy check |
| **Scope** | Implicit (whatever key allows) | Explicit manifest declaration |
| **Audit** | Application logs (if any) | Immutable, structured audit trail |
| **Egress Control** | None | Network-level filtering |
| **Revocation** | Rotate API keys | Instant token/session revocation |
| **Human-in-the-Loop** | Not supported | Configurable approval gates |
| **Blast Radius** | Unlimited | Scoped to manifest |
| **Compliance** | Manual attestation | Policy-as-code, auditable |

---

## Architecture Principles

1. **Defense in Depth**: Multiple independent security layers (identity, policy, egress, audit)
2. **Least Privilege by Default**: Agents start with zero capabilities; everything is opt-in
3. **Fail Closed**: Unknown actions are denied; network errors = deny
4. **Immutable Audit**: All decisions logged; logs cannot be modified by agents
5. **Human Sovereignty**: Critical actions require human approval
6. **Manifest Portability**: Same manifest works across runtimes (local, Kubernetes, serverless)

---

## Roadmap

### Completed
- [x] **v0.1: Local Proxy** — Single-binary proxy for local development
- [x] **Policy Engine** — Declarative YAML policies with tool allowlists
- [x] **Human-in-the-Loop** — Native OS prompts for sensitive operations
- [x] **DLP Scanner** — Redact sensitive data in tool responses
- [x] **Audit Logging** — Immutable JSONL audit trail
- [x] **Cursor Integration** — `--generate-cursor-config` for easy setup
- [x] **Rate Limiting** — Per-tool rate limits
- [x] **Monitor Mode** — Dry-run policy testing

### In Progress
- [ ] **v0.2: Kubernetes Sidecar** — Inject AIP as a sidecar container
- [ ] **Helm Chart** — Easy Kubernetes deployment

### Planned
- [ ] **v0.3: MCP Integration** — Native MCP transport with AIP policy layer
- [ ] **v0.4: Multi-Agent Support** — Agent-to-agent authentication and delegation
- [ ] **v1.0: OIDC Federation** — Full identity provider integration (Okta, Auth0, Google)
- [ ] **v1.1: Policy Language** — Rego/CEL support for complex authorization rules
- [ ] **v1.2: Observability Stack** — Prometheus metrics, OpenTelemetry traces
- [ ] **VS Code Extension** — Native VS Code integration

---

## Documentation

| Document | Description |
|----------|-------------|
| [Quickstart](docs/quickstart.md) | Get running in 5 minutes |
| [Architecture](docs/architecture.md) | Deep dive into AIP design |
| [Policy Reference](docs/policy-reference.md) | Complete YAML schema |
| [Integration Guide](docs/integration-guide.md) | Cursor, VS Code, Claude Desktop |
| [Contributing](CONTRIBUTING.md) | How to contribute |
| [Security](SECURITY.md) | Vulnerability reporting |
| [Changelog](CHANGELOG.md) | Release history |

---

## Project Structure

```
agent-identity-protocol/
├── proxy/                   # Go implementation of AIP proxy
│   ├── cmd/aip-proxy/       # Main entry point
│   ├── pkg/
│   │   ├── audit/           # JSONL audit logging
│   │   ├── dlp/             # Data Loss Prevention scanner
│   │   ├── policy/          # Policy engine
│   │   ├── protocol/        # JSON-RPC types
│   │   └── ui/              # Human-in-the-loop prompts
│   ├── examples/            # Example policies
│   ├── test/                # Test fixtures
│   └── Makefile
├── docs/                    # Extended documentation
│   ├── quickstart.md
│   ├── architecture.md
│   ├── policy-reference.md
│   └── integration-guide.md
├── scripts/                 # Utility scripts
└── .github/                 # CI/CD, templates, configs
    ├── workflows/
    ├── ISSUE_TEMPLATE/
    └── PULL_REQUEST_TEMPLATE.md
```

---

## Getting Started

### Quick Install

```bash
# Clone and build
git clone https://github.com/ArangoGutierrez/agent-identity-protocol.git
cd agent-identity-protocol/proxy
make build

# Verify installation
./bin/aip --help
```

### Basic Usage

```bash
# Run with a policy file and target MCP server
./bin/aip --policy examples/agent.yaml --target "python3 mcp_server.py"

# Verbose mode for debugging
./bin/aip --policy examples/agent.yaml --target "npx @mcp/server" --verbose
```

**See the full walkthrough:** [Quickstart Guide](docs/quickstart.md) — includes a working test with a dummy MCP server.

### CLI Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--target` | Command to run as MCP server (required) | — |
| `--policy` | Path to agent.yaml policy file | `agent.yaml` |
| `--audit` | Path to audit log file | `aip-audit.jsonl` |
| `--verbose` | Enable detailed logging | `false` |
| `--generate-cursor-config` | Output Cursor IDE config JSON | `false` |

### Known Limitations

#### Signal Propagation to Subprocess

When AIP receives `SIGTERM` or `SIGINT` (e.g., Ctrl+C), it forwards the signal to the subprocess. However, **signals may not propagate correctly in all scenarios**:

| Scenario | Behavior | Workaround |
|----------|----------|------------|
| Direct binary (`python server.py`) | ✅ Signal propagates correctly | None needed |
| Shell wrapper (`sh -c "python ..."`) | ⚠️ Signal may kill shell only | Avoid shell wrappers |
| Docker container (`docker run ...`) | ⚠️ Container may orphan | Use `--rm` and `--init` flags |

**Docker Best Practices:**

```bash
# GOOD: Container dies with proxy
aip --target "docker run --rm --init -i mcp-server:latest" --policy policy.yaml

# BAD: Container may orphan
aip --target "docker run mcp-server:latest" --policy policy.yaml
```

The `--rm` flag removes the container on exit, and `--init` ensures signals propagate to the container's PID 1.

See `examples/docker-wrapper.yaml` for a complete Docker policy example.

---

## The "Sudo for AI" Demo

This is how you prove AIP works. We'll wrap a GPU/Kubernetes MCP server with policy enforcement and see interactive approval in action.

### Step 1: Create a Policy

```yaml
# gpu-policy.yaml
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: gpu-policy
spec:
  mode: enforce
  allowed_tools:
    - list_gpus
    - get_gpu_metrics
  tool_rules:
    - tool: list_gpus
      rate_limit: "10/minute"
    - tool: run_training
      action: ask  # Interactive popup!
    - tool: delete_resources
      action: block
```

### Step 2: Generate Cursor Config

```bash
./bin/aip --generate-cursor-config \
  --policy ./gpu-policy.yaml \
  --target "/path/to/your/k8s-gpu-mcp-server"
```

Output:
```json
{
  "mcpServers": {
    "protected-tool": {
      "command": "/path/to/aip",
      "args": [
        "--policy", "/path/to/gpu-policy.yaml",
        "--target", "/path/to/your/k8s-gpu-mcp-server"
      ]
    }
  }
}
```

### Step 3: Add to Cursor

Paste the JSON into `~/.cursor/mcp.json` and restart Cursor.

### Step 4: The Demo

| You Ask | What Happens | Result |
|---------|--------------|--------|
| "List my GPUs" | Tool: `list_gpus` → Allowed | ✅ Success |
| "Run a training job" | Tool: `run_training` → Popup: "Allow?" | 🔔 User decides |
| Click "Deny" | Request blocked | ❌ "User Denied" |
| Click "Allow" | Request forwarded | ✅ Training starts |
| "Delete all pods" | Tool: `delete_resources` → Policy block | ❌ "Forbidden by policy" |

**You just gave your AI agent a permission system.** Every sensitive action requires explicit approval.

---

## Contributing

AIP is an open specification. We welcome contributions from:

- **Security researchers**: Threat modeling, attack surface analysis
- **Platform engineers**: Kubernetes operators, cloud integrations  
- **AI/ML engineers**: Agent framework integrations
- **Compliance teams**: Regulatory mapping (SOC2, GDPR, HIPAA)

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## Prior Art & Inspiration

AIP builds on established security patterns:

- **[SPIFFE/SPIRE](https://spiffe.io/)**: Workload identity framework — AIP extends this to agent identity
- **[Open Policy Agent](https://www.openpolicyagent.org/)**: Policy-as-code — AIP's policy engine draws from OPA's design
- **[Istio](https://istio.io/)**: Service mesh authorization — AIP applies mesh principles to agent traffic
- **[AWS IAM](https://aws.amazon.com/iam/)**: Fine-grained permissions — AIP manifests are IAM policies for agents
- **[OAuth 2.0 / OIDC](https://openid.net/connect/)**: Token-based identity — AIP leverages OIDC for federation

---

## License

Apache License 2.0 — See [LICENSE](LICENSE) for details.

Enterprise-friendly with patent grants. Use it, fork it, build on it.

---

## Contact

- **GitHub Issues**: Bug reports, feature requests
- **Discussions**: Architecture questions, use case exploration
- **Security**: arangogutierrez@gmail.com (for responsible disclosure)

---

<p align="center">
  <em>"Trust, but verify—automatically, at every tool call."</em>
</p>
