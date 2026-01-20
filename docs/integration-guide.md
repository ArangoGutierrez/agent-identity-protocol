# Integration Guide

How to integrate AIP with your development environment and AI tools.

## Table of Contents

- [Cursor IDE](#cursor-ide)
- [VS Code](#vs-code)
- [Claude Desktop](#claude-desktop)
- [Command Line](#command-line)
- [Docker](#docker)
- [Kubernetes](#kubernetes)

## Cursor IDE

Cursor natively supports MCP servers. AIP wraps your MCP servers with policy enforcement.

### Quick Setup

1. **Build AIP**:
   ```bash
   cd proxy
   make build
   ```

2. **Create a policy** (`~/.config/aip/my-policy.yaml`):
   ```yaml
   apiVersion: aip.io/v1alpha1
   kind: AgentPolicy
   metadata:
     name: cursor-policy
   spec:
     mode: enforce
     allowed_tools:
       - read_file
       - list_directory
       - search_files
     tool_rules:
       - tool: write_file
         action: ask  # Prompt for approval
       - tool: exec_command
         action: block
   ```

3. **Generate Cursor config**:
   ```bash
   ./bin/aip --generate-cursor-config \
     --policy ~/.config/aip/my-policy.yaml \
     --target "npx @modelcontextprotocol/server-filesystem /path/to/workspace"
   ```

4. **Add to Cursor settings** (`~/.cursor/mcp.json`):
   ```json
   {
     "mcpServers": {
       "protected-filesystem": {
         "command": "/path/to/aip",
         "args": [
           "--policy", "/Users/you/.config/aip/my-policy.yaml",
           "--target", "npx @modelcontextprotocol/server-filesystem /path/to/workspace"
         ]
       }
     }
   }
   ```

5. **Restart Cursor** to load the new MCP server.

### Example: GPU Server with Policy

For your Kubernetes GPU MCP server:

```yaml
# gpu-policy.yaml
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: k8s-gpu-policy
spec:
  mode: enforce
  allowed_tools:
    - list_gpus
    - get_gpu_metrics
    - list_pods
  tool_rules:
    - tool: list_gpus
      rate_limit: "10/minute"
    - tool: run_training
      action: ask
    - tool: delete_pod
      action: block
```

Generate config:
```bash
./bin/aip --generate-cursor-config \
  --policy ./gpu-policy.yaml \
  --target "/path/to/k8s-gpu-mcp-server"
```

### Demo: "Sudo for AI"

1. Ask Cursor: **"List my GPUs."**
   - Tool: `list_gpus`
   - Policy: Allowed with rate limit
   - Result: ✅ Success

2. Ask Cursor: **"Run a training job on GPU 0."**
   - Tool: `run_training`
   - Policy: `action: ask`
   - Result: 🔔 Popup appears
   - Click "Deny" → ❌ "User Denied"

## VS Code

VS Code doesn't have native MCP support, but you can use AIP with extensions like Continue or Cody.

### With Continue Extension

1. Install [Continue](https://continue.dev/) extension

2. Configure Continue to use your MCP server via AIP:

   ```json
   // ~/.continue/config.json
   {
     "models": [...],
     "mcpServers": {
       "protected-server": {
         "command": "/path/to/aip",
         "args": [
           "--policy", "/path/to/policy.yaml",
           "--target", "your-mcp-server-command"
         ]
       }
     }
   }
   ```

## Claude Desktop

Claude Desktop supports MCP servers through its configuration.

### Setup

1. Locate config file:
   - macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
   - Windows: `%APPDATA%\Claude\claude_desktop_config.json`

2. Add AIP-wrapped server:

   ```json
   {
     "mcpServers": {
       "protected-tools": {
         "command": "/path/to/aip",
         "args": [
           "--policy", "/path/to/policy.yaml",
           "--target", "npx @modelcontextprotocol/server-filesystem /"
         ]
       }
     }
   }
   ```

3. Restart Claude Desktop.

## Command Line

### Direct Usage

Run AIP directly to wrap any MCP server:

```bash
# Basic usage
./aip --target "python my_server.py" --policy policy.yaml

# Verbose mode for debugging
./aip --target "npx @mcp/server" --policy policy.yaml --verbose

# Monitor mode (dry run)
./aip --target "docker run mcp/server" --policy monitor-policy.yaml
```

### Piping Requests

Test with manual JSON-RPC:

```bash
echo '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"list_files"},"id":1}' | \
  ./aip --target "python echo_server.py" --policy policy.yaml --verbose
```

### Viewing Audit Logs

```bash
# All events
cat aip-audit.jsonl | jq '.'

# Blocked requests only
cat aip-audit.jsonl | jq 'select(.decision == "BLOCK")'

# Tool usage summary
cat aip-audit.jsonl | jq -r '.tool' | sort | uniq -c | sort -rn
```

## Docker

### Building the Image

```dockerfile
# Dockerfile
FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY proxy/ .
RUN go build -o /aip ./cmd/aip-proxy

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /aip /usr/local/bin/aip
ENTRYPOINT ["aip"]
```

Build:
```bash
docker build -t aip:latest .
```

### Running with Docker

```bash
# Mount policy and run
docker run -v $(pwd)/policy.yaml:/policy.yaml \
  aip:latest \
  --policy /policy.yaml \
  --target "your-mcp-command"
```

### Docker Compose

```yaml
# docker-compose.yaml
version: '3.8'
services:
  mcp-proxy:
    image: aip:latest
    volumes:
      - ./policy.yaml:/policy.yaml:ro
      - ./audit:/var/log/aip
    command:
      - --policy
      - /policy.yaml
      - --target
      - "python /app/server.py"
      - --audit
      - /var/log/aip/audit.jsonl
    stdin_open: true
    tty: true
```

## Kubernetes

### Sidecar Pattern

Deploy AIP as a sidecar container alongside your MCP server:

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mcp-server
spec:
  template:
    spec:
      containers:
        # Main MCP server
        - name: mcp-server
          image: your-mcp-server:latest
          # Server listens on stdio or a socket
          
        # AIP sidecar
        - name: aip-proxy
          image: aip:latest
          args:
            - --policy
            - /config/policy.yaml
            - --target
            - "nc localhost 8080"  # Connect to main server
            - --audit
            - /var/log/aip/audit.jsonl
          volumeMounts:
            - name: policy
              mountPath: /config
            - name: audit
              mountPath: /var/log/aip
              
      volumes:
        - name: policy
          configMap:
            name: aip-policy
        - name: audit
          emptyDir: {}
```

### ConfigMap for Policy

```yaml
# configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: aip-policy
data:
  policy.yaml: |
    apiVersion: aip.io/v1alpha1
    kind: AgentPolicy
    metadata:
      name: k8s-policy
    spec:
      mode: enforce
      allowed_tools:
        - list_pods
        - get_logs
      tool_rules:
        - tool: delete_pod
          action: block
```

### Helm Chart (Future)

A Helm chart is planned for easier Kubernetes deployment. Track progress in [GitHub Issues](https://github.com/ArangoGutierrez/agent-identity-protocol/issues).

## Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| "Policy file not found" | Use absolute path to policy.yaml |
| "Empty response from server" | Check target command is correct |
| "Permission denied" | Ensure aip binary is executable |
| "Headless environment" | `action: ask` will auto-deny without display |

### Debug Mode

Enable verbose logging to diagnose issues:

```bash
./aip --target "..." --policy policy.yaml --verbose 2>debug.log
```

Check `debug.log` for detailed message flow.

### Audit Log Analysis

```bash
# Recent blocked requests
tail -100 aip-audit.jsonl | jq 'select(.decision == "BLOCK")'

# DLP events
jq 'select(.event_type == "DLP_TRIGGERED")' aip-audit.jsonl
```
