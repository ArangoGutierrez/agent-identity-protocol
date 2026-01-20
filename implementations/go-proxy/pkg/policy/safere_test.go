package policy

import (
	"testing"
	"time"
)

func TestSafeCompile_ValidPatterns(t *testing.T) {
	validPatterns := []string{
		`^https://github\.com/.*`,
		`^SELECT\s+.*`,
		`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`,
		`(?i)(api_key|secret|password)\s*[:=]\s*['"]?([a-zA-Z0-9-_]+)['"]?`,
		`(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`,
		`^(staging|prod)$`,
		`^/api/.*`,
	}

	for _, pattern := range validPatterns {
		t.Run(pattern[:min(20, len(pattern))], func(t *testing.T) {
			re, err := SafeCompile(pattern, 0)
			if err != nil {
				t.Errorf("SafeCompile(%q) failed: %v", pattern, err)
			}
			if re == nil {
				t.Errorf("SafeCompile(%q) returned nil regex", pattern)
			}
		})
	}
}

func TestSafeCompile_InvalidPatterns(t *testing.T) {
	invalidPatterns := []struct {
		name    string
		pattern string
	}{
		{"unclosed bracket", `[invalid`},
		{"unclosed paren", `(unclosed`},
		{"invalid repetition", `a**`},
		{"unmatched paren", `a)b`},
		{"bad escape in class", `[\c]`},
	}

	for _, tt := range invalidPatterns {
		t.Run(tt.name, func(t *testing.T) {
			re, err := SafeCompile(tt.pattern, 0)
			if err == nil {
				t.Errorf("SafeCompile(%q) should fail", tt.pattern)
			}
			if re != nil {
				t.Errorf("SafeCompile(%q) should return nil regex on error", tt.pattern)
			}
		})
	}
}

func TestSafeCompile_Timeout(t *testing.T) {
	// Test with very short timeout - even simple patterns might timeout
	// This tests the timeout mechanism, not actual ReDoS
	pattern := `^simple$`

	// Should succeed with reasonable timeout
	re, err := SafeCompile(pattern, 100*time.Millisecond)
	if err != nil {
		t.Errorf("SafeCompile with 100ms timeout failed: %v", err)
	}
	if re == nil {
		t.Error("Expected non-nil regex")
	}
}

func TestSafeCompile_DefaultTimeout(t *testing.T) {
	// Test that passing 0 uses default timeout
	pattern := `^test$`
	re, err := SafeCompile(pattern, 0) // 0 = use default
	if err != nil {
		t.Errorf("SafeCompile with default timeout failed: %v", err)
	}
	if re == nil {
		t.Error("Expected non-nil regex")
	}
}

func TestMustSafeCompile_Success(t *testing.T) {
	// Should not panic for valid patterns
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("MustSafeCompile panicked unexpectedly: %v", r)
		}
	}()

	re := MustSafeCompile(`^valid$`)
	if re == nil {
		t.Error("Expected non-nil regex")
	}
}

func TestMustSafeCompile_Panic(t *testing.T) {
	// Should panic for invalid patterns
	defer func() {
		if r := recover(); r == nil {
			t.Error("MustSafeCompile should have panicked for invalid pattern")
		}
	}()

	MustSafeCompile(`[invalid`)
}

func TestValidateRegexComplexity_Valid(t *testing.T) {
	validPatterns := []string{
		`^https://.*`,
		`[a-z]+`,
		`\d{3}-\d{2}-\d{4}`,
		`(?i)password`,
	}

	for _, pattern := range validPatterns {
		t.Run(pattern, func(t *testing.T) {
			err := ValidateRegexComplexity(pattern)
			if err != nil {
				t.Errorf("ValidateRegexComplexity(%q) unexpected error: %v", pattern, err)
			}
		})
	}
}

func TestValidateRegexComplexity_TooLong(t *testing.T) {
	// Create a pattern longer than 1000 chars
	longPattern := "^"
	for i := 0; i < 1001; i++ {
		longPattern += "a"
	}
	longPattern += "$"

	err := ValidateRegexComplexity(longPattern)
	if err == nil {
		t.Error("ValidateRegexComplexity should reject very long patterns")
	}
}

func TestValidateRegexComplexity_NestedQuantifiers(t *testing.T) {
	// These patterns have nested quantifiers that can cause ReDoS
	dangerousPatterns := []string{
		`(a+)+`,
		`(a*)+`,
		`(a+)*`,
		`(a*)*`,
	}

	for _, pattern := range dangerousPatterns {
		t.Run(pattern, func(t *testing.T) {
			err := ValidateRegexComplexity(pattern)
			if err == nil {
				t.Errorf("ValidateRegexComplexity(%q) should detect nested quantifiers", pattern)
			}
		})
	}
}

// TestSafeCompile_RealWorldPatterns tests patterns from actual agent.yaml examples
func TestSafeCompile_RealWorldPatterns(t *testing.T) {
	realWorldPatterns := []struct {
		name    string
		pattern string
	}{
		{"email", `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`},
		{"aws_key", `(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`},
		{"generic_secret", `(?i)(api_key|secret|password)\s*[:=]\s*['"]?([a-zA-Z0-9-_]+)['"]?`},
		{"ssn", `\b\d{3}-\d{2}-\d{4}\b`},
		{"credit_card", `\b(?:\d{4}[- ]?){3}\d{4}\b`},
		{"github_token", `ghp_[a-zA-Z0-9]{36}`},
		{"private_key", `-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`},
		{"github_url", `^https://github\.com/.*`},
		{"select_query", `^SELECT\s+.*`},
		{"safe_commands", `^(ls|cat|echo|pwd)\s.*`},
		{"api_endpoint", `^https://api\.github\.com/.*`},
		{"http_method", `^(GET|POST)$`},
		{"environment", `^(staging|prod)$`},
	}

	for _, tt := range realWorldPatterns {
		t.Run(tt.name, func(t *testing.T) {
			// First validate complexity
			if err := ValidateRegexComplexity(tt.pattern); err != nil {
				t.Logf("Complexity warning for %s: %v", tt.name, err)
			}

			// Then compile with timeout
			re, err := SafeCompile(tt.pattern, 0)
			if err != nil {
				t.Errorf("SafeCompile failed for %s: %v", tt.name, err)
			}
			if re == nil {
				t.Errorf("SafeCompile returned nil for %s", tt.name)
			}
		})
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
