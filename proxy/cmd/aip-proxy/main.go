// AIP - Agent Identity Protocol Proxy
//
// A policy enforcement proxy for MCP (Model Context Protocol) that intercepts
// tool calls and enforces security policies between AI agents and tool servers.
//
// Architecture:
//
//	┌─────────────┐     ┌──────────────────┐     ┌─────────────────┐
//	│  MCP Client │────▶│    AIP Proxy     │────▶│   MCP Server    │
//	│   (Agent)   │◀────│  Policy Engine   │◀────│  (Subprocess)   │
//	└─────────────┘     └──────────────────┘     └─────────────────┘
//
// Features:
//   - Tool allowlist enforcement (only permitted tools can be called)
//   - Argument validation with regex patterns
//   - Human-in-the-Loop approval (action: ask) via native OS dialogs
//   - DLP (Data Loss Prevention) output scanning and redaction
//   - JSONL audit logging for compliance and debugging
//   - Monitor mode for testing policies without enforcement
//
// Usage:
//
//	# Basic usage - wrap an MCP server with policy enforcement
//	aip --target "python mcp_server.py" --policy policy.yaml
//
//	# Generate Cursor IDE configuration
//	aip --generate-cursor-config --policy policy.yaml --target "docker run mcp/server"
//
//	# Monitor mode (log violations but don't block)
//	aip --target "npx @mcp/server" --policy monitor.yaml --verbose
//
// For more information: https://github.com/ArangoGutierrez/agent-identity-protocol
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/ArangoGutierrez/agent-identity-protocol/proxy/pkg/audit"
	"github.com/ArangoGutierrez/agent-identity-protocol/proxy/pkg/dlp"
	"github.com/ArangoGutierrez/agent-identity-protocol/proxy/pkg/policy"
	"github.com/ArangoGutierrez/agent-identity-protocol/proxy/pkg/protocol"
	"github.com/ArangoGutierrez/agent-identity-protocol/proxy/pkg/ui"
)

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

// Config holds the proxy's runtime configuration parsed from flags.
type Config struct {
	// Target is the command to run as the MCP server subprocess.
	// Example: "python server.py" or "npx @modelcontextprotocol/server-filesystem"
	Target string

	// PolicyPath is the path to the agent.yaml policy file.
	PolicyPath string

	// AuditPath is the path to the audit log file.
	// Default: "aip-audit.jsonl" in current directory.
	// CRITICAL: Must NOT be stdout or any path that writes to stdout.
	AuditPath string

	// Verbose enables detailed logging of intercepted messages.
	Verbose bool

	// GenerateCursorConfig prints Cursor IDE MCP configuration and exits.
	GenerateCursorConfig bool
}

func parseFlags() *Config {
	cfg := &Config{}

	// Custom usage message
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `AIP - Agent Identity Protocol Proxy

A security proxy that enforces policies on MCP tool calls.

USAGE:
  aip --target "command" --policy policy.yaml [options]

EXAMPLES:
  # Wrap an MCP server with policy enforcement
  aip --target "python mcp_server.py" --policy policy.yaml

  # Run in monitor mode (logs violations but doesn't block)
  aip --target "npx @mcp/server" --policy monitor.yaml --verbose

  # Generate configuration for Cursor IDE
  aip --generate-cursor-config --policy policy.yaml --target "docker run mcp/server"

MODES:
  Enforce (default):
    Blocks tool calls that violate policy rules.
    Returns JSON-RPC error (-32001) to the client.

  Monitor (spec.mode: monitor in policy):
    Logs violations but allows all requests through.
    Use for testing policies before enforcement.

AUDIT LOGS:
  All tool calls are logged to the audit file (default: aip-audit.jsonl).
  Each entry includes: timestamp, tool, args, decision, violation status.
  View logs: cat aip-audit.jsonl | jq '.'
  Find violations: cat aip-audit.jsonl | jq 'select(.violation == true)'

OPTIONS:
`)
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
POLICY FILE:
  See examples/ directory for policy templates:
    - read-only.yaml         Only allow read operations
    - monitor-mode.yaml      Log everything, block nothing
    - gemini-jack-defense.yaml  Defense against prompt injection

For more information: https://github.com/ArangoGutierrez/agent-identity-protocol
`)
	}

	flag.StringVar(&cfg.Target, "target", "", "Command to run as MCP server (required)")
	flag.StringVar(&cfg.PolicyPath, "policy", "agent.yaml", "Path to policy YAML file")
	flag.StringVar(&cfg.AuditPath, "audit", "aip-audit.jsonl", "Path to audit log file")
	flag.BoolVar(&cfg.Verbose, "verbose", false, "Enable verbose logging to stderr")
	flag.BoolVar(&cfg.GenerateCursorConfig, "generate-cursor-config", false, "Print Cursor MCP config JSON and exit")

	flag.Parse()

	// If generating config, we need both target and policy
	if cfg.GenerateCursorConfig {
		if cfg.Target == "" || cfg.PolicyPath == "" {
			fmt.Fprintln(os.Stderr, "Error: --generate-cursor-config requires both --target and --policy")
			os.Exit(1)
		}
		return cfg
	}

	// Normal mode requires target
	if cfg.Target == "" {
		fmt.Fprintln(os.Stderr, "Error: --target flag is required")
		fmt.Fprintln(os.Stderr, "Run 'aip -h' for usage information")
		os.Exit(1)
	}

	return cfg
}

// -----------------------------------------------------------------------------
// Main Entry Point
// -----------------------------------------------------------------------------

func main() {
	cfg := parseFlags()

	// Handle config generation mode
	if cfg.GenerateCursorConfig {
		generateCursorConfig(cfg)
		return
	}

	// CRITICAL STREAM SAFETY:
	// - stdout is RESERVED for JSON-RPC transport (client ↔ server)
	// - stderr is used for operational logs (via log.Logger)
	// - audit logs go to a FILE (via audit.Logger)
	// NEVER write logs to stdout - it corrupts the JSON-RPC stream

	// Initialize operational logging to stderr
	// stderr is safe because it doesn't interfere with JSON-RPC on stdout
	logger := log.New(os.Stderr, "[aip-proxy] ", log.LstdFlags|log.Lmsgprefix)

	// Load the policy file
	engine := policy.NewEngine()
	if err := engine.LoadFromFile(cfg.PolicyPath); err != nil {
		logger.Fatalf("Failed to load policy: %v", err)
	}
	logger.Printf("Loaded policy: %s", engine.GetPolicyName())
	logger.Printf("Allowed tools: %v", engine.GetAllowedTools())
	logger.Printf("Policy mode: %s", engine.GetMode())

	// Initialize audit logger (writes to file, NEVER stdout)
	auditMode := audit.PolicyModeEnforce
	if engine.IsMonitorMode() {
		auditMode = audit.PolicyModeMonitor
	}
	auditLogger, err := audit.NewLogger(&audit.Config{
		FilePath: cfg.AuditPath,
		Mode:     auditMode,
	})
	if err != nil {
		logger.Fatalf("Failed to initialize audit logger: %v", err)
	}
	defer auditLogger.Close()
	logger.Printf("Audit logging to: %s", cfg.AuditPath)

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)

	// Start the subprocess
	proxy, err := NewProxy(ctx, cfg, engine, logger, auditLogger)
	if err != nil {
		logger.Fatalf("Failed to start proxy: %v", err)
	}

	// Handle shutdown signals
	go func() {
		sig := <-sigChan
		logger.Printf("Received signal %v, shutting down...", sig)
		cancel()
		proxy.Shutdown()
	}()

	// Run the proxy (blocks until subprocess exits)
	exitCode := proxy.Run()

	// Ensure audit logs are flushed before exit
	if err := auditLogger.Sync(); err != nil {
		logger.Printf("Warning: failed to sync audit log: %v", err)
	}

	os.Exit(exitCode)
}

// -----------------------------------------------------------------------------
// Cursor Config Generator
// -----------------------------------------------------------------------------

// generateCursorConfig prints a JSON configuration snippet for Cursor IDE's
// MCP settings file (~/.cursor/mcp.json). This makes it easy to integrate
// AIP with Cursor by wrapping MCP servers with policy enforcement.
func generateCursorConfig(cfg *Config) {
	// Get absolute path to current executable
	execPath, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to get executable path: %v\n", err)
		os.Exit(1)
	}
	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to resolve executable path: %v\n", err)
		os.Exit(1)
	}

	// Get absolute path to policy file
	policyPath, err := filepath.Abs(cfg.PolicyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to resolve policy path: %v\n", err)
		os.Exit(1)
	}

	// Verify policy file exists
	if _, err := os.Stat(policyPath); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Warning: policy file does not exist: %s\n", policyPath)
	}

	// Build the configuration structure
	config := map[string]interface{}{
		"mcpServers": map[string]interface{}{
			"protected-tool": map[string]interface{}{
				"command": execPath,
				"args": []string{
					"--policy", policyPath,
					"--target", cfg.Target,
				},
			},
		},
	}

	// Pretty print JSON
	output, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to generate JSON: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(output))
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Add the above JSON to ~/.cursor/mcp.json")
	fmt.Fprintln(os.Stderr, "Then restart Cursor to enable the protected MCP server.")
}

// -----------------------------------------------------------------------------
// Proxy Implementation
// -----------------------------------------------------------------------------

// Proxy manages the subprocess and IO goroutines.
//
// The proxy is the core "Man-in-the-Middle" component. It:
//  1. Spawns the target MCP server as a subprocess
//  2. Intercepts messages flowing from client (stdin) to server (subprocess)
//  3. Applies policy checks to tool/call requests
//  4. Passes through allowed requests, blocks forbidden ones
//  5. Prompts user for approval on action="ask" rules (Human-in-the-Loop)
//  6. Scans downstream responses for sensitive data (DLP) and redacts
//  7. Logs all decisions to the audit log file (NEVER stdout)
type Proxy struct {
	ctx         context.Context
	cfg         *Config
	engine      *policy.Engine
	logger      *log.Logger
	auditLogger *audit.Logger
	prompter    *ui.Prompter
	dlpScanner  *dlp.Scanner

	// cmd is the subprocess running the target MCP server
	cmd *exec.Cmd

	// subStdin is the pipe to write to the subprocess's stdin
	subStdin io.WriteCloser

	// subStdout is the pipe to read from the subprocess's stdout
	subStdout io.ReadCloser

	// wg tracks the IO goroutines for clean shutdown
	wg sync.WaitGroup

	// mu protects concurrent writes to stdout
	// CRITICAL: Only JSON-RPC responses go to stdout, never logs
	mu sync.Mutex
}

// NewProxy creates and starts a new proxy instance.
//
// This function:
//  1. Parses the target command into executable and arguments
//  2. Creates the subprocess with piped stdin/stdout
//  3. Initializes the user prompter for Human-in-the-Loop approval
//  4. Initializes the DLP scanner for output redaction
//  5. Starts the subprocess
//
// The subprocess inherits our stderr for error output visibility.
// The auditLogger is used to record all policy decisions to a file.
func NewProxy(ctx context.Context, cfg *Config, engine *policy.Engine, logger *log.Logger, auditLogger *audit.Logger) (*Proxy, error) {
	// Parse the target command
	// Simple space-split; doesn't handle quoted args (use shell wrapper if needed)
	parts := strings.Fields(cfg.Target)
	if len(parts) == 0 {
		return nil, fmt.Errorf("empty target command")
	}

	// Create the subprocess command
	cmd := exec.CommandContext(ctx, parts[0], parts[1:]...)

	// Get pipes for subprocess communication
	subStdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	subStdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	// Subprocess stderr goes to our stderr for visibility
	cmd.Stderr = os.Stderr

	// Initialize the user prompter for Human-in-the-Loop approval
	// Check for headless environment and log a warning
	prompter := ui.NewPrompter(nil) // Use default config (60s timeout)
	if ui.IsHeadless() {
		logger.Printf("Warning: Running in headless environment; action=ask rules will auto-deny")
	}

	// Initialize DLP scanner for output redaction
	var dlpScanner *dlp.Scanner
	dlpCfg := engine.GetDLPConfig()
	if dlpCfg != nil && dlpCfg.IsEnabled() {
		dlpScanner, err = dlp.NewScanner(dlpCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize DLP scanner: %w", err)
		}
		logger.Printf("DLP enabled with %d patterns: %v", dlpScanner.PatternCount(), dlpScanner.PatternNames())
	}

	// Start the subprocess
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start subprocess: %w", err)
	}

	logger.Printf("Started subprocess PID %d: %s", cmd.Process.Pid, cfg.Target)

	return &Proxy{
		ctx:         ctx,
		cfg:         cfg,
		engine:      engine,
		logger:      logger,
		auditLogger: auditLogger,
		prompter:    prompter,
		dlpScanner:  dlpScanner,
		cmd:         cmd,
		subStdin:    subStdin,
		subStdout:   subStdout,
	}, nil
}

// Run starts the IO handling goroutines and waits for completion.
//
// Returns the subprocess exit code (0 on success, non-zero on error).
func (p *Proxy) Run() int {
	// Start the downstream goroutine (Server → Client)
	// This copies subprocess stdout to our stdout (passthrough)
	p.wg.Add(1)
	go p.handleDownstream()

	// Start the upstream goroutine (Client → Server)
	// This intercepts stdin, applies policy, forwards or blocks
	p.wg.Add(1)
	go p.handleUpstream()

	// Wait for subprocess to exit
	err := p.cmd.Wait()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode()
		}
		p.logger.Printf("Subprocess error: %v", err)
		return 1
	}

	// Wait for IO goroutines to finish
	p.wg.Wait()

	return 0
}

// Shutdown performs graceful termination of the subprocess.
func (p *Proxy) Shutdown() {
	if p.cmd.Process != nil {
		p.logger.Printf("Terminating subprocess PID %d", p.cmd.Process.Pid)
		// Send SIGTERM first for graceful shutdown
		_ = p.cmd.Process.Signal(syscall.SIGTERM)
	}
}

// -----------------------------------------------------------------------------
// Downstream Handler (Server → Client) - DLP INTERCEPTION POINT
// -----------------------------------------------------------------------------

// handleDownstream reads from subprocess stdout, applies DLP scanning, and
// forwards to our stdout.
//
// DLP (Data Loss Prevention) scanning inspects tool responses for sensitive
// information (PII, API keys, secrets) and redacts matches before the response
// reaches the client. This prevents accidental data exfiltration.
//
// Flow:
//  1. Read JSON-RPC message from subprocess stdout
//  2. Attempt to parse as JSON-RPC response
//  3. If valid JSON-RPC with result, scan content for sensitive data
//  4. Replace matches with [REDACTED:<RuleName>]
//  5. Log DLP events to audit trail
//  6. Forward (potentially modified) response to client stdout
//
// Robustness: If the tool outputs invalid JSON or non-JSON data (e.g., logs),
// we pass it through unchanged to avoid breaking the stream.
//
// This goroutine runs until the subprocess stdout is closed (subprocess exits).
func (p *Proxy) handleDownstream() {
	defer p.wg.Done()

	// Use buffered reader for efficient reading
	reader := bufio.NewReader(p.subStdout)

	for {
		// Read line-by-line (JSON-RPC messages are newline-delimited)
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if err != io.EOF {
				p.logger.Printf("Downstream read error: %v", err)
			}
			return
		}

		if p.cfg.Verbose {
			p.logger.Printf("← [downstream raw] %s", strings.TrimSpace(string(line)))
		}

		// Apply DLP scanning if enabled
		outputLine := line
		if p.dlpScanner != nil && p.dlpScanner.IsEnabled() {
			outputLine = p.applyDLP(line)
		}

		// Write to stdout (use mutex to prevent interleaving with upstream errors)
		p.mu.Lock()
		_, writeErr := os.Stdout.Write(outputLine)
		p.mu.Unlock()

		if writeErr != nil {
			p.logger.Printf("Downstream write error: %v", writeErr)
			return
		}
	}
}

// applyDLP scans a downstream JSON-RPC response for sensitive data and redacts.
//
// The function handles MCP tool call responses which have this structure:
//
//	{
//	  "jsonrpc": "2.0",
//	  "id": 1,
//	  "result": {
//	    "content": [
//	      {"type": "text", "text": "...potentially sensitive data..."}
//	    ]
//	  }
//	}
//
// We scan and redact the "text" fields within content items.
//
// If the input is not valid JSON or not a response with result, we return
// it unchanged to avoid breaking the stream.
func (p *Proxy) applyDLP(line []byte) []byte {
	// First, try to parse as generic JSON to check structure
	var msg map[string]json.RawMessage
	if err := json.Unmarshal(line, &msg); err != nil {
		// Not valid JSON - pass through unchanged (might be log output)
		if p.cfg.Verbose {
			p.logger.Printf("DLP: Non-JSON output, passing through")
		}
		return line
	}

	// Check if this is a JSON-RPC response with a result field
	resultRaw, hasResult := msg["result"]
	if !hasResult {
		// No result field - might be an error response or notification, pass through
		return line
	}

	// Try to parse the result to find content
	var result struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}

	if err := json.Unmarshal(resultRaw, &result); err != nil {
		// Result is not in expected format - try full-string scan as fallback
		return p.applyDLPFullScan(line)
	}

	// No content array - try full-string scan
	if len(result.Content) == 0 {
		return p.applyDLPFullScan(line)
	}

	// Scan each text field for sensitive data
	anyRedacted := false
	var allEvents []dlp.RedactionEvent

	for i := range result.Content {
		if result.Content[i].Type == "text" || result.Content[i].Text != "" {
			redacted, events := p.dlpScanner.Redact(result.Content[i].Text)
			if len(events) > 0 {
				anyRedacted = true
				allEvents = append(allEvents, events...)
				result.Content[i].Text = redacted
			}
		}
	}

	if !anyRedacted {
		// No redactions needed - return original line
		return line
	}

	// Log DLP events
	for _, event := range allEvents {
		p.logger.Printf("DLP_TRIGGERED: Rule %q matched %d time(s), redacted",
			event.RuleName, event.MatchCount)
		p.auditLogger.LogDLPEvent(event.RuleName, event.MatchCount)
	}

	// Reconstruct the JSON-RPC response with redacted content
	return p.reconstructResponse(line, result.Content)
}

// applyDLPFullScan performs string-level DLP scan on the entire JSON line.
// Used as a fallback when the response doesn't match expected MCP structure.
func (p *Proxy) applyDLPFullScan(line []byte) []byte {
	redacted, events := p.dlpScanner.Redact(string(line))
	if len(events) == 0 {
		return line
	}

	// Log DLP events
	for _, event := range events {
		p.logger.Printf("DLP_TRIGGERED (full-scan): Rule %q matched %d time(s), redacted",
			event.RuleName, event.MatchCount)
		p.auditLogger.LogDLPEvent(event.RuleName, event.MatchCount)
	}

	// Ensure we maintain the newline delimiter
	output := []byte(redacted)
	if len(output) > 0 && output[len(output)-1] != '\n' {
		output = append(output, '\n')
	}
	return output
}

// reconstructResponse rebuilds the JSON-RPC response with redacted content.
func (p *Proxy) reconstructResponse(originalLine []byte, redactedContent []struct {
	Type string `json:"type"`
	Text string `json:"text"`
}) []byte {
	// Parse the original message to preserve all fields
	var msg map[string]json.RawMessage
	if err := json.Unmarshal(originalLine, &msg); err != nil {
		// Should not happen since we already validated, but be safe
		return originalLine
	}

	// Parse and update the result
	var result map[string]json.RawMessage
	if err := json.Unmarshal(msg["result"], &result); err != nil {
		return originalLine
	}

	// Re-encode the redacted content
	contentJSON, err := json.Marshal(redactedContent)
	if err != nil {
		return originalLine
	}
	result["content"] = contentJSON

	// Re-encode the result
	resultJSON, err := json.Marshal(result)
	if err != nil {
		return originalLine
	}
	msg["result"] = resultJSON

	// Re-encode the full message
	outputJSON, err := json.Marshal(msg)
	if err != nil {
		return originalLine
	}

	// Append newline delimiter
	return append(outputJSON, '\n')
}

// -----------------------------------------------------------------------------
// Upstream Handler (Client → Server) - THE POLICY ENFORCEMENT POINT
// -----------------------------------------------------------------------------

// handleUpstream reads from stdin, applies policy checks, and either forwards
// to the subprocess or returns an error response.
//
// This is the critical "Man-in-the-Middle" interception point where policy
// enforcement happens. The flow is:
//
//  1. Read JSON-RPC message from stdin (client/agent)
//  2. Decode the message to inspect the method
//  3. If method is "tools/call":
//     a. Extract the tool name from params
//     b. Check engine.IsAllowed(toolName, args)
//     c. Log the decision to audit file (NEVER stdout)
//     d. If mode=ENFORCE AND violation: BLOCK (return error to stdout)
//     e. If mode=MONITOR AND violation: ALLOW (forward) but log as dry-run block
//     f. If no violation: ALLOW (forward)
//  4. For other methods: passthrough to subprocess
//
// CRITICAL STDOUT SAFETY:
//   - ONLY JSON-RPC messages go to stdout (responses to client)
//   - Audit logs go to FILE via auditLogger
//   - Operational logs go to stderr via logger
//   - NEVER use fmt.Println, log.Println, or similar that write to stdout
func (p *Proxy) handleUpstream() {
	defer p.wg.Done()
	defer p.subStdin.Close() // Close subprocess stdin when we're done

	reader := bufio.NewReader(os.Stdin)

	for {
		// Read a complete JSON-RPC message (newline-delimited)
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if err != io.EOF {
				p.logger.Printf("Upstream read error: %v", err)
			}
			return
		}

		if len(strings.TrimSpace(string(line))) == 0 {
			continue // Skip empty lines
		}

		// Attempt to decode as JSON-RPC request
		var req protocol.Request
		if err := json.Unmarshal(line, &req); err != nil {
			// Not valid JSON-RPC; pass through anyway (might be a notification)
			p.logger.Printf("Warning: failed to parse message: %v", err)
			if _, err := p.subStdin.Write(line); err != nil {
				p.logger.Printf("Upstream write error: %v", err)
				return
			}
			continue
		}

		if p.cfg.Verbose {
			p.logger.Printf("→ [upstream] method=%s id=%s", req.Method, string(req.ID))
		}

		// POLICY CHECK: Is this a tool call that needs authorization?
		if req.IsToolCall() {
			toolName := req.GetToolName()
			toolArgs := req.GetToolArgs()
			p.logger.Printf("Tool call intercepted: %s", toolName)

			decision := p.engine.IsAllowed(toolName, toolArgs)

			// Handle Human-in-the-Loop (ASK) action first
			if decision.Action == policy.ActionAsk {
				p.logger.Printf("ASK: Requesting user approval for tool %q...", toolName)

				// Prompt user via native OS dialog
				approved := p.prompter.AskUserContext(p.ctx, toolName, toolArgs)

				// Log the user's decision
				if approved {
					p.logger.Printf("ASK_APPROVED: User approved tool %q", toolName)
					p.auditLogger.LogToolCall(
						toolName,
						toolArgs,
						audit.DecisionAllow,
						false, // Not a violation - user explicitly approved
						"",
						"",
					)
					// Fall through to forward the request
				} else {
					p.logger.Printf("ASK_DENIED: User denied tool %q (or timeout)", toolName)
					p.auditLogger.LogToolCall(
						toolName,
						toolArgs,
						audit.DecisionBlock,
						true, // Treat as violation for audit purposes
						"",
						"",
					)
					p.sendErrorResponse(protocol.NewUserDeniedError(req.ID, toolName))
					continue // Do not forward to subprocess
				}
			} else {
				// Standard policy decision (not ASK)

				// Determine audit decision type for logging
				var auditDecision audit.Decision
				if !decision.ViolationDetected {
					auditDecision = audit.DecisionAllow
				} else if decision.Allowed {
					// Violation detected but allowed through = monitor mode
					auditDecision = audit.DecisionAllowMonitor
				} else {
					auditDecision = audit.DecisionBlock
				}

				// Log to audit file (NEVER to stdout)
				p.auditLogger.LogToolCall(
					toolName,
					toolArgs,
					auditDecision,
					decision.ViolationDetected,
					decision.FailedArg,
					decision.FailedRule,
				)

				// Handle the decision based on mode
				if !decision.Allowed {
					// Check for rate limiting first
					if decision.Action == policy.ActionRateLimited {
						p.logger.Printf("RATE_LIMITED: Tool %q exceeded rate limit", toolName)
						p.auditLogger.LogToolCall(
							toolName,
							toolArgs,
							audit.DecisionRateLimited,
							true,
							"",
							"",
						)
						p.sendErrorResponse(protocol.NewRateLimitedError(req.ID, toolName))
						continue // Do not forward to subprocess
					}
					// BLOCKED (enforce mode with violation)
					if decision.FailedArg != "" {
						p.logger.Printf("BLOCKED: Tool %q argument %q failed validation (pattern: %s)",
							toolName, decision.FailedArg, decision.FailedRule)
						p.sendErrorResponse(protocol.NewArgumentError(req.ID, toolName, decision.FailedArg, decision.FailedRule))
					} else {
						p.logger.Printf("BLOCKED: Tool %q not allowed by policy", toolName)
						p.sendErrorResponse(protocol.NewForbiddenError(req.ID, toolName))
					}
					continue // Do not forward to subprocess
				}

				// Request is allowed (either no violation, or monitor mode)
				if decision.ViolationDetected {
					// MONITOR MODE: Violation detected but allowing through (dry run)
					p.logger.Printf("ALLOW_MONITOR (dry-run): Tool %q would be blocked, reason: %s",
						toolName, decision.Reason)
				} else {
					// Clean allow, no violation
					p.logger.Printf("ALLOWED: Tool %q permitted by policy", toolName)
				}
			}
		}

		// Forward the message to subprocess stdin
		if _, err := p.subStdin.Write(line); err != nil {
			p.logger.Printf("Upstream write error: %v", err)
			return
		}
	}
}

// sendErrorResponse marshals and writes a JSON-RPC error response to stdout.
//
// This is used to respond to blocked tool calls without involving the subprocess.
// The response is written directly to our stdout (back to the client).
func (p *Proxy) sendErrorResponse(resp *protocol.Response) {
	data, err := json.Marshal(resp)
	if err != nil {
		p.logger.Printf("Failed to marshal error response: %v", err)
		return
	}

	// Add newline for JSON-RPC message delimiter
	data = append(data, '\n')

	// Use mutex to prevent interleaving with downstream messages
	p.mu.Lock()
	defer p.mu.Unlock()

	if _, err := os.Stdout.Write(data); err != nil {
		p.logger.Printf("Failed to write error response: %v", err)
	}
}
