// Package policy tests for the AIP policy engine.
package policy

import (
	"testing"
)

// TestGeminiJackDefense tests the "GeminiJack" attack defense.
//
// Attack scenario: An attacker tricks an agent into calling fetch_url with
// a malicious URL like "https://attacker.com/steal" instead of the intended
// "https://github.com/..." URL.
//
// Defense: The policy engine validates the url argument against a regex
// that only allows GitHub URLs.
func TestGeminiJackDefense(t *testing.T) {
	policyYAML := `
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: gemini-jack-defense-test
spec:
  tool_rules:
    - tool: fetch_url
      allow_args:
        url: "^https://github\\.com/.*"
`

	engine := NewEngine()
	if err := engine.Load([]byte(policyYAML)); err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	tests := []struct {
		name        string
		tool        string
		args        map[string]any
		wantAllowed bool
		wantFailArg string
	}{
		{
			name:        "Valid GitHub URL should pass",
			tool:        "fetch_url",
			args:        map[string]any{"url": "https://github.com/my-repo"},
			wantAllowed: true,
		},
		{
			name:        "Attacker URL should fail",
			tool:        "fetch_url",
			args:        map[string]any{"url": "https://attacker.com/steal"},
			wantAllowed: false,
			wantFailArg: "url",
		},
		{
			name:        "HTTP GitHub URL should fail (not https)",
			tool:        "fetch_url",
			args:        map[string]any{"url": "http://github.com/my-repo"},
			wantAllowed: false,
			wantFailArg: "url",
		},
		{
			name:        "GitHub subdomain attack should fail",
			tool:        "fetch_url",
			args:        map[string]any{"url": "https://github.com.evil.com/my-repo"},
			wantAllowed: false,
			wantFailArg: "url",
		},
		{
			name:        "Missing url argument should fail",
			tool:        "fetch_url",
			args:        map[string]any{},
			wantAllowed: false,
			wantFailArg: "url",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.IsAllowed(tt.tool, tt.args)

			if result.Allowed != tt.wantAllowed {
				t.Errorf("IsAllowed() = %v, want %v", result.Allowed, tt.wantAllowed)
			}

			if tt.wantFailArg != "" && result.FailedArg != tt.wantFailArg {
				t.Errorf("FailedArg = %q, want %q", result.FailedArg, tt.wantFailArg)
			}
		})
	}
}

// TestToolLevelDeny tests that tools not in allowed_tools are denied.
func TestToolLevelDeny(t *testing.T) {
	policyYAML := `
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: tool-level-test
spec:
  allowed_tools:
    - safe_tool
`

	engine := NewEngine()
	if err := engine.Load([]byte(policyYAML)); err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	tests := []struct {
		name        string
		tool        string
		wantAllowed bool
	}{
		{"Allowed tool passes", "safe_tool", true},
		{"Allowed tool case-insensitive", "SAFE_TOOL", true},
		{"Unknown tool denied", "dangerous_tool", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.IsAllowed(tt.tool, nil)
			if result.Allowed != tt.wantAllowed {
				t.Errorf("IsAllowed(%q) = %v, want %v", tt.tool, result.Allowed, tt.wantAllowed)
			}
		})
	}
}

// TestToolWithNoArgRulesAllowsAllArgs tests that tools in tool_rules
// without allow_args allow all arguments.
func TestToolWithNoArgRulesAllowsAllArgs(t *testing.T) {
	policyYAML := `
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: no-arg-rules-test
spec:
  allowed_tools:
    - unrestricted_tool
`

	engine := NewEngine()
	if err := engine.Load([]byte(policyYAML)); err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	// Tool is allowed, no arg rules = allow any args
	result := engine.IsAllowed("unrestricted_tool", map[string]any{
		"any_arg":    "any_value",
		"another":    12345,
		"dangerous":  "../../etc/passwd",
	})

	if !result.Allowed {
		t.Errorf("Expected unrestricted_tool to allow all args, got denied")
	}
}

// TestMultipleArgConstraints tests that multiple arguments are all validated.
func TestMultipleArgConstraints(t *testing.T) {
	policyYAML := `
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: multi-arg-test
spec:
  tool_rules:
    - tool: run_query
      allow_args:
        database: "^(prod|staging)$"
        query: "^SELECT\\s+.*"
`

	engine := NewEngine()
	if err := engine.Load([]byte(policyYAML)); err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	tests := []struct {
		name        string
		args        map[string]any
		wantAllowed bool
		wantFailArg string
	}{
		{
			name:        "Valid SELECT on prod",
			args:        map[string]any{"database": "prod", "query": "SELECT * FROM users"},
			wantAllowed: true,
		},
		{
			name:        "Valid SELECT on staging",
			args:        map[string]any{"database": "staging", "query": "SELECT id FROM orders"},
			wantAllowed: true,
		},
		{
			name:        "DROP query should fail",
			args:        map[string]any{"database": "prod", "query": "DROP TABLE users"},
			wantAllowed: false,
			wantFailArg: "query",
		},
		{
			name:        "Invalid database should fail",
			args:        map[string]any{"database": "master", "query": "SELECT * FROM users"},
			wantAllowed: false,
			wantFailArg: "database",
		},
		{
			name:        "DELETE query should fail",
			args:        map[string]any{"database": "prod", "query": "DELETE FROM users"},
			wantAllowed: false,
			wantFailArg: "query",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.IsAllowed("run_query", tt.args)

			if result.Allowed != tt.wantAllowed {
				t.Errorf("IsAllowed() = %v, want %v", result.Allowed, tt.wantAllowed)
			}

			if !tt.wantAllowed && tt.wantFailArg != "" && result.FailedArg != tt.wantFailArg {
				t.Errorf("FailedArg = %q, want %q", result.FailedArg, tt.wantFailArg)
			}
		})
	}
}

// TestInvalidRegexReturnsError tests that invalid regex patterns cause Load() to fail.
func TestInvalidRegexReturnsError(t *testing.T) {
	policyYAML := `
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: invalid-regex-test
spec:
  tool_rules:
    - tool: bad_tool
      allow_args:
        pattern: "[invalid(regex"
`

	engine := NewEngine()
	err := engine.Load([]byte(policyYAML))

	if err == nil {
		t.Error("Expected Load() to fail with invalid regex, but it succeeded")
	}
}

// TestArgToString tests conversion of various types to strings.
func TestArgToString(t *testing.T) {
	tests := []struct {
		input any
		want  string
	}{
		{"hello", "hello"},
		{float64(42), "42"},
		{float64(3.14), "3.14"},
		{true, "true"},
		{false, "false"},
		{int(100), "100"},
	}

	for _, tt := range tests {
		got := argToString(tt.input)
		if got != tt.want {
			t.Errorf("argToString(%v) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// TestToolRulesImplicitlyAllowTool tests that defining a tool_rule
// implicitly adds the tool to allowed_tools.
func TestToolRulesImplicitlyAllowTool(t *testing.T) {
	policyYAML := `
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: implicit-allow-test
spec:
  # Note: fetch_url NOT in allowed_tools, but has a tool_rule
  tool_rules:
    - tool: fetch_url
      allow_args:
        url: "^https://.*"
`

	engine := NewEngine()
	if err := engine.Load([]byte(policyYAML)); err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	// Tool should be allowed because it has a rule defined
	result := engine.IsAllowed("fetch_url", map[string]any{"url": "https://example.com"})
	if !result.Allowed {
		t.Error("Expected fetch_url to be implicitly allowed via tool_rules")
	}
}
