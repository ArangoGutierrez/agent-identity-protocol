// Package audit tests for the AIP audit logger.
package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNewLoggerCreatesFile tests that NewLogger creates the audit file.
func TestNewLoggerCreatesFile(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test-audit.jsonl")

	logger, err := NewLogger(&Config{
		FilePath: logPath,
		Mode:     PolicyModeEnforce,
	})
	if err != nil {
		t.Fatalf("NewLogger() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	// Verify file was created
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		t.Error("NewLogger() did not create audit file")
	}
}

// TestLoggerRejectsStdout tests that the logger refuses to write to stdout.
func TestLoggerRejectsStdout(t *testing.T) {
	stdoutPaths := []string{
		"/dev/stdout",
		"/dev/fd/1",
		"/proc/self/fd/1",
	}

	for _, path := range stdoutPaths {
		_, err := NewLogger(&Config{FilePath: path})
		if err == nil {
			t.Errorf("NewLogger(%q) should have failed but succeeded", path)
		}
		if !strings.Contains(err.Error(), "stdout") {
			t.Errorf("Error should mention stdout, got: %v", err)
		}
	}
}

// TestLogWritesToFile tests that Log() writes entries to the file.
func TestLogWritesToFile(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test-audit.jsonl")

	logger, err := NewLogger(&Config{
		FilePath: logPath,
		Mode:     PolicyModeEnforce,
	})
	if err != nil {
		t.Fatalf("NewLogger() error = %v", err)
	}

	// Log an entry
	logger.Log(&Entry{
		Direction:  DirectionUpstream,
		Method:     "tools/call",
		Tool:       "test_tool",
		Args:       map[string]any{"arg1": "value1"},
		Decision:   DecisionBlock,
		Violation:  true,
		FailedArg:  "arg1",
		FailedRule: "^allowed.*",
	})

	// Close to flush
	if err := logger.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	// Read and verify
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	// Should contain at least one JSON line
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) < 1 {
		t.Fatal("Expected at least 1 log line")
	}

	// Parse the last line (slog output)
	var logEntry map[string]any
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &logEntry); err != nil {
		t.Fatalf("Failed to parse log line: %v", err)
	}

	// Verify key fields are present
	if logEntry["tool"] != "test_tool" {
		t.Errorf("tool = %v, want test_tool", logEntry["tool"])
	}
	if logEntry["decision"] != string(DecisionBlock) {
		t.Errorf("decision = %v, want BLOCK", logEntry["decision"])
	}
	if logEntry["violation"] != true {
		t.Errorf("violation = %v, want true", logEntry["violation"])
	}
}

// TestLogToolCallConvenience tests the LogToolCall convenience method.
func TestLogToolCallConvenience(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test-audit.jsonl")

	logger, err := NewLogger(&Config{
		FilePath: logPath,
		Mode:     PolicyModeMonitor,
	})
	if err != nil {
		t.Fatalf("NewLogger() error = %v", err)
	}

	// Use convenience method
	logger.LogToolCall(
		"delete_file",
		map[string]any{"path": "/etc/passwd"},
		DecisionAllowMonitor,
		true,
		"path",
		"^/home/.*",
	)

	if err := logger.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	// Read and verify
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	if !strings.Contains(string(data), "delete_file") {
		t.Error("Log should contain tool name")
	}
	if !strings.Contains(string(data), "ALLOW_MONITOR") {
		t.Error("Log should contain ALLOW_MONITOR decision")
	}
}

// TestNopLogger tests that NopLogger doesn't crash.
func TestNopLogger(t *testing.T) {
	logger := NewNopLogger()

	// Should not panic
	logger.Log(&Entry{
		Direction: DirectionUpstream,
		Tool:      "test",
		Decision:  DecisionAllow,
	})

	logger.LogToolCall("test", nil, DecisionAllow, false, "", "")
	logger.SetMode(PolicyModeMonitor)

	if err := logger.Close(); err != nil {
		t.Errorf("NopLogger.Close() error = %v", err)
	}
}

// TestGetSetMode tests mode getter and setter.
func TestGetSetMode(t *testing.T) {
	logger := NewNopLogger()

	// Default mode
	if logger.GetMode() != PolicyModeEnforce {
		t.Errorf("Default mode = %v, want %v", logger.GetMode(), PolicyModeEnforce)
	}

	// Set to monitor
	logger.SetMode(PolicyModeMonitor)
	if logger.GetMode() != PolicyModeMonitor {
		t.Errorf("After SetMode, mode = %v, want %v", logger.GetMode(), PolicyModeMonitor)
	}
}

// TestDefaultConfig tests that DefaultConfig returns sensible defaults.
func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.FilePath != "aip-audit.jsonl" {
		t.Errorf("FilePath = %q, want aip-audit.jsonl", cfg.FilePath)
	}
	if cfg.Mode != PolicyModeEnforce {
		t.Errorf("Mode = %v, want %v", cfg.Mode, PolicyModeEnforce)
	}
}
