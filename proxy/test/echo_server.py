#!/usr/bin/env python3
"""
Dummy MCP server that echoes back JSON-RPC requests.

This simulates a real MCP server for testing the AIP proxy.
It reads JSON lines from stdin and echoes them back to stdout
wrapped in a JSON-RPC response.
"""
import sys
import json

def main():
    # Flush stdout immediately for real-time output
    sys.stdout.reconfigure(line_buffering=True)
    
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        
        try:
            request = json.loads(line)
            # Echo back as a JSON-RPC response
            response = {
                "jsonrpc": "2.0",
                "id": request.get("id"),
                "result": {
                    "echo": request,
                    "message": "Request received by echo_server"
                }
            }
            print(json.dumps(response), flush=True)
        except json.JSONDecodeError as e:
            error_response = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32700,
                    "message": f"Parse error: {e}"
                }
            }
            print(json.dumps(error_response), flush=True)

if __name__ == "__main__":
    main()
