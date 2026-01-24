# Identity Management Guide

## Overview

AIP v1alpha2 introduces **Identity Tokens** to provide cryptographic proof of session identity. This prevents unauthorized agents from hijacking sessions or replaying requests.

Identity management in AIP provides:
1.  **Session Binding**: Cryptographically binds requests to a specific agent session.
2.  **Automatic Rotation**: Short-lived tokens are automatically rotated to limit exposure.
3.  **Replay Prevention**: Nonces prevent captured tokens from being reused.
4.  **Policy Integrity**: Ensures the policy hasn't changed during the session.

## When to Use Identity Tokens

You should enable identity tokens when:

*   **Multi-tenant environments**: Multiple agents share the same infrastructure or policy.
*   **Zero-trust deployments**: You don't trust the network between the agent and the proxy.
*   **Audit requirements**: You need to correlate specific tool calls to a verified session.
*   **Remote validation**: You are using the AIP Server for centralized policy enforcement.

## Configuration

Identity is configured in the `spec.identity` section of your policy file.

```yaml
apiVersion: aip.io/v1alpha2
kind: AgentPolicy
metadata:
  name: secure-agent
spec:
  identity:
    enabled: true
    token_ttl: "10m"          # Tokens valid for 10 minutes
    rotation_interval: "8m"   # Rotate after 8 minutes
    require_token: true       # Block requests without tokens
    session_binding: "strict" # Bind to process + policy + host
    audience: "https://api.company.com" # Prevent token reuse across services
```

### Key Fields

| Field | Description | Recommended Value |
|-------|-------------|-------------------|
| `enabled` | Activates identity management | `true` |
| `token_ttl` | How long a token is valid | `"5m"` to `"15m"` |
| `rotation_interval` | When to issue a new token | `80%` of `token_ttl` |
| `require_token` | Whether to enforce token presence | `true` (after testing) |
| `session_binding` | What to bind the session to | See below |

## Session Binding Modes

The `session_binding` field controls how strictly the session is tied to the execution environment.

| Mode | Binds To | Use Case | Security Level |
|------|----------|----------|----------------|
| `process` | OS Process ID (PID) | Local agents, single machine | Low |
| `policy` | Policy Hash | Distributed agents, k8s pods | Medium |
| `strict` | PID + Policy + Hostname | High-security, static VMs | High |

### Choosing a Mode

*   **Use `process`** for local development or simple CLI tools.
*   **Use `policy`** for Kubernetes or containerized environments where PIDs and hostnames change (ephemeral).
*   **Use `strict`** for long-running VMs or bare-metal servers where the environment is stable.

## Token Lifecycle

1.  **Issuance**: When the agent starts (or first requests a token), AIP issues a signed JWT.
2.  **Usage**: The agent includes the token in the `Authorization: Bearer <token>` header (or internal context).
3.  **Rotation**: Before the token expires (at `rotation_interval`), AIP automatically issues a new token.
4.  **Validation**: For every request, AIP checks:
    *   Signature validity
    *   Expiration time
    *   Policy hash match
    *   Session binding match
    *   Nonce uniqueness (replay check)

## Example: Securing Multi-Tenant Deployments

In a multi-tenant setup, you might have different agents for different teams using the same AIP proxy instance (or cluster).

**Team A Policy (`team-a.yaml`)**:
```yaml
metadata:
  name: team-a-agent
spec:
  identity:
    enabled: true
    audience: "https://aip.internal/team-a"
    session_binding: "policy"
```

**Team B Policy (`team-b.yaml`)**:
```yaml
metadata:
  name: team-b-agent
spec:
  identity:
    enabled: true
    audience: "https://aip.internal/team-b"
    session_binding: "policy"
```

By setting different `audience` values and using `session_binding: "policy"`, you ensure that a token stolen from Team A cannot be used to impersonate Team B, even if they share the same underlying infrastructure.

## Common Pitfalls

1.  **Rotation Interval too close to TTL**: If `rotation_interval` is equal to or greater than `token_ttl`, tokens will expire before they can be rotated, causing request failures. Keep a buffer (e.g., 20%).
2.  **Strict binding in Kubernetes**: Using `session_binding: "strict"` in Kubernetes will cause session failures if a pod restarts (new PID/hostname). Use `policy` binding instead.
3.  **Ignoring Audience**: Always set `audience` in production to prevent "confused deputy" attacks where a token for one service is used for another.
