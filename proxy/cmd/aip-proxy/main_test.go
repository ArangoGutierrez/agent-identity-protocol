// Package main tests for the AIP proxy.
//
// These tests verify the integration between the proxy, policy engine,
// and audit logger, particularly around monitor mode behavior.
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArangoGutierrez/agent-identity-protocol/proxy/pkg/audit"
	"github.com/ArangoGutierrez/agent-identity-protocol/proxy/pkg/policy"
	"github.com/ArangoGutierrez/agent-identity-protocol/proxy/pkg/protocol"
)

// TestMonitorModeIntegration tests the full integration of monitor mode:
// 1. Configure policy in monitor mode
// 2. Send a "blocked" request (e.g., dangerous_tool)
// 3. Assert request would be PASSED to child process
// 4. Assert audit log contains decision: "ALLOW_MONITOR" and violation: true
func TestMonitorModeIntegration(t *testing.T) {
	// Setup: Create temp directory for audit log
	tmpDir := t.TempDir()
	auditPath := filepath.Join(tmpDir, "test-audit.jsonl")

	// Step 1: Configure policy in monitor mode
	policyYAML := `
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: monitor-integration-test
spec:
  mode: monitor
  allowed_tools:
    - safe_tool
`

	// Load policy
	engine := policy.NewEngine()
	if err := engine.Load([]byte(policyYAML)); err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	// Verify monitor mode is active
	if !engine.IsMonitorMode() {
		t.Fatal("Expected monitor mode to be active")
	}

	// Create audit logger
	auditLogger, err := audit.NewLogger(&audit.Config{
		FilePath: auditPath,
		Mode:     audit.PolicyModeMonitor,
	})
	if err != nil {
		t.Fatalf("Failed to create audit logger: %v", err)
	}

	// Step 2: Simulate sending a "blocked" request
	// In a real proxy, this would be a tools/call for dangerous_tool
	toolName := "dangerous_tool"
	toolArgs := map[string]any{"command": "rm -rf /"}

	// Check policy decision
	decision := engine.IsAllowed(toolName, toolArgs)

	// Step 3: Assert request would be PASSED (Allowed=true in monitor mode)
	if !decision.Allowed {
		t.Errorf("In monitor mode, request should be allowed; got Allowed=%v", decision.Allowed)
	}

	// Verify violation was detected
	if !decision.ViolationDetected {
		t.Error("ViolationDetected should be true for blocked tool")
	}

	// Determine audit decision type
	var auditDecision audit.Decision
	if !decision.ViolationDetected {
		auditDecision = audit.DecisionAllow
	} else if decision.Allowed {
		auditDecision = audit.DecisionAllowMonitor
	} else {
		auditDecision = audit.DecisionBlock
	}

	// Log the decision
	auditLogger.LogToolCall(
		toolName,
		toolArgs,
		auditDecision,
		decision.ViolationDetected,
		decision.FailedArg,
		decision.FailedRule,
	)

	// Close logger to flush
	if err := auditLogger.Close(); err != nil {
		t.Fatalf("Failed to close audit logger: %v", err)
	}

	// Step 4: Read and verify audit log
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("Failed to read audit log: %v", err)
	}

	// Parse the log line
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) < 1 {
		t.Fatal("Expected at least 1 log line in audit file")
	}

	var logEntry map[string]any
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &logEntry); err != nil {
		t.Fatalf("Failed to parse log line: %v", err)
	}

	// Verify decision is ALLOW_MONITOR
	if logEntry["decision"] != string(audit.DecisionAllowMonitor) {
		t.Errorf("decision = %v, want %v", logEntry["decision"], audit.DecisionAllowMonitor)
	}

	// Verify violation is true
	if logEntry["violation"] != true {
		t.Errorf("violation = %v, want true", logEntry["violation"])
	}

	// Verify tool name
	if logEntry["tool"] != "dangerous_tool" {
		t.Errorf("tool = %v, want dangerous_tool", logEntry["tool"])
	}
}

// TestEnforceModeBlocksRequest tests that enforce mode properly blocks requests.
func TestEnforceModeBlocksRequest(t *testing.T) {
	tmpDir := t.TempDir()
	auditPath := filepath.Join(tmpDir, "test-audit.jsonl")

	policyYAML := `
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: enforce-integration-test
spec:
  mode: enforce
  allowed_tools:
    - safe_tool
`

	engine := policy.NewEngine()
	if err := engine.Load([]byte(policyYAML)); err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	auditLogger, err := audit.NewLogger(&audit.Config{
		FilePath: auditPath,
		Mode:     audit.PolicyModeEnforce,
	})
	if err != nil {
		t.Fatalf("Failed to create audit logger: %v", err)
	}

	// Try to use a blocked tool
	decision := engine.IsAllowed("dangerous_tool", nil)

	// In enforce mode, should be blocked
	if decision.Allowed {
		t.Error("In enforce mode, dangerous_tool should be blocked")
	}
	if !decision.ViolationDetected {
		t.Error("ViolationDetected should be true")
	}

	// Log the block
	auditLogger.LogToolCall("dangerous_tool", nil, audit.DecisionBlock, true, "", "")
	auditLogger.Close()

	// Verify audit log
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("Failed to read audit log: %v", err)
	}

	if !strings.Contains(string(data), "BLOCK") {
		t.Error("Audit log should contain BLOCK decision")
	}
}

// TestStdoutSafetyVerification documents and verifies stdout safety.
//
// CRITICAL: This test serves as documentation that stdout is NEVER used for logs.
// The JSON-RPC protocol requires stdout to be clean for transport.
//
// Verification checklist:
// - [x] audit.Logger writes to FILE only, rejects stdout paths
// - [x] main.go uses log.New(os.Stderr, ...) for operational logs
// - [x] handleUpstream only writes JSON-RPC responses to stdout via p.sendErrorResponse
// - [x] handleDownstream passthrough is the only other stdout writer
// - [x] Comments throughout codebase document this requirement
func TestStdoutSafetyVerification(t *testing.T) {
	// Test 1: Audit logger rejects stdout paths
	stdoutPaths := []string{"/dev/stdout", "/dev/fd/1", "/proc/self/fd/1"}
	for _, path := range stdoutPaths {
		_, err := audit.NewLogger(&audit.Config{FilePath: path})
		if err == nil {
			t.Errorf("Audit logger should reject stdout path %q", path)
		}
	}

	// Test 2: Verify protocol types only write proper JSON-RPC
	// (sendErrorResponse outputs valid JSON-RPC error responses)
	resp := protocol.NewForbiddenError([]byte(`1`), "test_tool")
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Failed to marshal response: %v", err)
	}

	// Should be valid JSON
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Response is not valid JSON: %v", err)
	}

	// Should have jsonrpc field
	if parsed["jsonrpc"] != "2.0" {
		t.Error("Response missing jsonrpc: 2.0 field")
	}

	t.Log("Stdout safety verification passed:")
	t.Log("  - Audit logger rejects stdout paths")
	t.Log("  - JSON-RPC responses are valid JSON")
	t.Log("  - See code comments for full documentation")
}

// TestAuditLogFormat verifies the audit log format matches the spec.
func TestAuditLogFormat(t *testing.T) {
	tmpDir := t.TempDir()
	auditPath := filepath.Join(tmpDir, "test-audit.jsonl")

	logger, err := audit.NewLogger(&audit.Config{
		FilePath: auditPath,
		Mode:     audit.PolicyModeMonitor,
	})
	if err != nil {
		t.Fatalf("NewLogger() error = %v", err)
	}

	// Log with all fields populated
	logger.Log(&audit.Entry{
		Direction:   audit.DirectionUpstream,
		Method:      "tools/call",
		Tool:        "delete_file",
		Args:        map[string]any{"path": "/etc/passwd"},
		Decision:    audit.DecisionBlock,
		PolicyMode:  audit.PolicyModeEnforce,
		Violation:   true,
		FailedArg:   "path",
		FailedRule:  "^/home/.*",
		PolicyName:  "test-policy",
		RequestID:   "req-123",
		ErrorReason: "path outside allowed directory",
	})

	logger.Close()

	// Read and verify all fields
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) < 1 {
		t.Fatal("Expected log entry")
	}

	var entry map[string]any
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &entry); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}

	// Verify required fields from spec
	requiredFields := []string{
		"timestamp",
		"direction",
		"tool",
		"decision",
		"policy_mode",
	}

	for _, field := range requiredFields {
		if _, ok := entry[field]; !ok {
			t.Errorf("Missing required field: %s", field)
		}
	}

	// Verify values
	if entry["direction"] != "upstream" {
		t.Errorf("direction = %v, want upstream", entry["direction"])
	}
	if entry["tool"] != "delete_file" {
		t.Errorf("tool = %v, want delete_file", entry["tool"])
	}
	if entry["decision"] != "BLOCK" {
		t.Errorf("decision = %v, want BLOCK", entry["decision"])
	}
	if entry["policy_mode"] != "enforce" {
		t.Errorf("policy_mode = %v, want enforce", entry["policy_mode"])
	}
}
