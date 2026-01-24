# Server-Side Validation Guide

## Overview

AIP v1alpha2 introduces **Server-Side Validation**, allowing you to decouple policy enforcement from the agent's runtime. Instead of running the AIP proxy locally with the agent, you can run a centralized AIP Server that validates tool calls over HTTP.

Benefits:
*   **Centralized Control**: Update policies in one place without redeploying agents.
*   **Audit Aggregation**: Collect audit logs from all agents in a single stream.
*   **Secret Protection**: Keep sensitive policy details (like regex patterns or protected paths) on the server.

## Architecture

```
[Agent / MCP Client]  --->  [AIP Server]  --->  [MCP Server]
       (HTTP)                 (HTTP)
```

The agent sends a validation request to the AIP Server. If approved, the agent proceeds to call the tool (or the AIP Server can proxy the call directly, depending on deployment).

## Configuration

To enable the server, configure the `spec.server` section in your policy.

```yaml
apiVersion: aip.io/v1alpha2
kind: AgentPolicy
metadata:
  name: centralized-policy
spec:
  server:
    enabled: true
    listen: "0.0.0.0:9443"    # Listen on all interfaces
    failover_mode: "fail_closed"
    tls:
      cert: "/etc/aip/certs/server.crt"
      key: "/etc/aip/certs/server.key"
```

## Setting up TLS (Production)

For any non-localhost deployment, **TLS is required**.

1.  **Generate Certificates**:
    ```bash
    openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes
    ```

2.  **Configure Policy**:
    Point the `tls.cert` and `tls.key` fields to your generated files.

3.  **Client Trust**:
    Ensure your agents trust the CA that signed the server certificate.

## Endpoints

The AIP Server exposes the following endpoints:

*   `POST /v1/validate`: The main validation endpoint. Accepts a tool call description and returns Allow/Block/Ask.
*   `GET /health`: Health check for load balancers.
*   `GET /metrics`: Prometheus metrics.
*   `GET /v1/jwks`: JSON Web Key Set for verifying identity tokens.

## Prometheus Metrics Integration

The server exposes standard Prometheus metrics at `/metrics`.

**Key Metrics**:

*   `aip_requests_total`: Total number of validation requests.
*   `aip_decisions_total{decision="allow|block"}`: Count of allowed vs blocked requests.
*   `aip_violations_total{type="..."}`: Detailed breakdown of policy violations.
*   `aip_request_duration_seconds`: Latency histogram.

**Example Prometheus Config**:

```yaml
scrape_configs:
  - job_name: 'aip-server'
    static_configs:
      - targets: ['aip-server:9443']
    scheme: https
    tls_config:
      insecure_skip_verify: false # Set to true only for self-signed
```

## Failover Modes

What happens if the AIP Server is unreachable?

| Mode | Behavior | Use Case |
|------|----------|----------|
| `fail_closed` | **Block** all requests. | High-security environments. Default. |
| `fail_open` | **Allow** all requests (log warning). | Development or non-critical tools. |
| `local_policy` | Fallback to a **local** policy file. | Hybrid deployments (best of both worlds). |

**Example: Local Policy Fallback**

```yaml
spec:
  server:
    enabled: true
    failover_mode: "local_policy"
    timeout: "2s"
```

In this mode, the agent tries the server first. If it times out after 2 seconds, it evaluates the request against the local policy file.

## Example: Centralized Policy Enforcement

1.  **Deploy AIP Server**:
    Run the AIP binary in "server mode" with your master policy.
    ```bash
    ./aip server --policy master-policy.yaml
    ```

2.  **Configure Agents**:
    Configure your agents to use the remote validator.
    ```bash
    export AIP_VALIDATOR_URL="https://aip-server:9443/v1/validate"
    ./agent ...
    ```

    *(Note: Client-side configuration depends on the specific MCP client implementation. See your client's documentation for AIP integration.)*
