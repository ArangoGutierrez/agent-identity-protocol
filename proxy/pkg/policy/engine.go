// Package policy implements the AIP policy engine for tool call authorization.
//
// The policy engine is the core security primitive of AIP. It evaluates every
// tool call against a declarative manifest (agent.yaml) and returns an allow/deny
// decision. This package provides a minimal MVP implementation that supports
// simple allow-list based authorization.
//
// Future versions will support:
//   - Deny lists and explicit deny rules
//   - Argument-level constraints (e.g., "only SELECT queries")
//   - Pattern matching (e.g., "github_*" allows all GitHub tools)
//   - Rate limiting enforcement
//   - CEL/Rego expressions for complex policies
package policy

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// -----------------------------------------------------------------------------
// Policy Configuration Types
// -----------------------------------------------------------------------------

// AgentPolicy represents the parsed agent.yaml manifest.
//
// This struct maps to the policy file that defines what an agent is allowed
// to do. In the MVP, we focus on the allowed_tools list for basic tool-level
// authorization.
//
// Example agent.yaml:
//
//	apiVersion: aip.io/v1alpha1
//	kind: AgentPolicy
//	metadata:
//	  name: code-review-agent
//	spec:
//	  allowed_tools:
//	    - github_get_repo
//	    - github_list_pulls
//	    - github_create_review
type AgentPolicy struct {
	// APIVersion identifies the policy schema version.
	// Current version: aip.io/v1alpha1
	APIVersion string `yaml:"apiVersion"`

	// Kind must be "AgentPolicy" for this struct.
	Kind string `yaml:"kind"`

	// Metadata contains identifying information about the policy.
	Metadata PolicyMetadata `yaml:"metadata"`

	// Spec contains the actual policy rules.
	Spec PolicySpec `yaml:"spec"`
}

// PolicyMetadata contains identifying information about the policy.
type PolicyMetadata struct {
	// Name is a human-readable identifier for the agent.
	Name string `yaml:"name"`

	// Version is the semantic version of this policy.
	Version string `yaml:"version,omitempty"`

	// Owner is the team/person responsible for this policy.
	Owner string `yaml:"owner,omitempty"`
}

// PolicySpec contains the actual authorization rules.
type PolicySpec struct {
	// AllowedTools is a list of tool names that the agent may invoke.
	// If a tool is not in this list, it will be blocked.
	// Supports exact matches only in MVP; patterns in future versions.
	AllowedTools []string `yaml:"allowed_tools"`

	// ToolRules defines granular argument-level validation for specific tools.
	// Each rule specifies regex patterns that arguments must match.
	// If a tool has a rule here, its arguments are validated; if not, only
	// tool-level allow/deny applies.
	ToolRules []ToolRule `yaml:"tool_rules,omitempty"`

	// DeniedTools is a list of tools that are explicitly forbidden.
	// Takes precedence over AllowedTools (deny wins).
	// TODO: Implement in v0.2
	DeniedTools []string `yaml:"denied_tools,omitempty"`
}

// ToolRule defines argument-level validation for a specific tool.
//
// Example YAML:
//
//	tool_rules:
//	  - tool: fetch_url
//	    allow_args:
//	      url: "^https://github\\.com/.*"
//	  - tool: run_query
//	    allow_args:
//	      query: "^SELECT\\s+.*"
type ToolRule struct {
	// Tool is the name of the tool this rule applies to.
	Tool string `yaml:"tool"`

	// AllowArgs maps argument names to regex patterns.
	// Each argument value must match its corresponding regex.
	// Key = argument name, Value = regex pattern string.
	AllowArgs map[string]string `yaml:"allow_args"`

	// compiledArgs holds pre-compiled regex patterns for performance.
	// Populated during Load() to avoid recompilation on every request.
	compiledArgs map[string]*regexp.Regexp
}

// -----------------------------------------------------------------------------
// Policy Engine
// -----------------------------------------------------------------------------

// Engine evaluates tool calls against the loaded policy.
//
// The engine is the "brain" of the AIP proxy. It maintains the parsed policy
// and provides fast lookups to determine if a tool call should be allowed.
//
// Thread-safety: The engine is safe for concurrent use after initialization.
// The allowedSet and toolRules maps are read-only after Load().
type Engine struct {
	// policy holds the parsed agent.yaml configuration.
	policy *AgentPolicy

	// allowedSet provides O(1) lookup for allowed tools.
	// Populated during Load() from policy.Spec.AllowedTools.
	allowedSet map[string]struct{}

	// toolRules provides O(1) lookup for tool-specific argument rules.
	// Key = normalized tool name, Value = ToolRule with compiled regexes.
	toolRules map[string]*ToolRule
}

// NewEngine creates a new policy engine instance.
//
// The engine is not usable until Load() or LoadFromFile() is called.
func NewEngine() *Engine {
	return &Engine{
		allowedSet: make(map[string]struct{}),
		toolRules:  make(map[string]*ToolRule),
	}
}

// Load parses a policy from YAML bytes and initializes the engine.
//
// This method builds the internal allowedSet for fast IsAllowed() lookups
// and compiles all regex patterns in tool_rules for argument validation.
// Tool names are normalized to lowercase for case-insensitive matching.
//
// Returns an error if:
//   - YAML parsing fails
//   - Required fields are missing
//   - Any regex pattern in allow_args is invalid
func (e *Engine) Load(data []byte) error {
	var policy AgentPolicy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return fmt.Errorf("failed to parse policy YAML: %w", err)
	}

	// Validate required fields
	if policy.APIVersion == "" {
		return fmt.Errorf("policy missing required field: apiVersion")
	}
	if policy.Kind != "AgentPolicy" {
		return fmt.Errorf("unexpected kind %q, expected AgentPolicy", policy.Kind)
	}

	// Build the allowed set for O(1) lookups
	// Normalize to lowercase for case-insensitive matching
	e.allowedSet = make(map[string]struct{}, len(policy.Spec.AllowedTools))
	for _, tool := range policy.Spec.AllowedTools {
		normalized := strings.ToLower(strings.TrimSpace(tool))
		e.allowedSet[normalized] = struct{}{}
	}

	// Compile tool rules with regex patterns
	e.toolRules = make(map[string]*ToolRule, len(policy.Spec.ToolRules))
	for i := range policy.Spec.ToolRules {
		rule := &policy.Spec.ToolRules[i]
		normalized := strings.ToLower(strings.TrimSpace(rule.Tool))

		// Compile all regex patterns for this tool
		rule.compiledArgs = make(map[string]*regexp.Regexp, len(rule.AllowArgs))
		for argName, pattern := range rule.AllowArgs {
			compiled, err := regexp.Compile(pattern)
			if err != nil {
				return fmt.Errorf("invalid regex for tool %q arg %q: %w", rule.Tool, argName, err)
			}
			rule.compiledArgs[argName] = compiled
		}

		e.toolRules[normalized] = rule

		// Implicitly add tool to allowed set if it has rules defined
		e.allowedSet[normalized] = struct{}{}
	}

	e.policy = &policy
	return nil
}

// LoadFromFile reads and parses a policy file from disk.
func (e *Engine) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read policy file %q: %w", path, err)
	}
	return e.Load(data)
}

// ValidationResult contains the result of a tool call authorization check.
type ValidationResult struct {
	Allowed    bool   // Whether the tool call is permitted
	FailedArg  string // Name of the argument that failed validation (if any)
	FailedRule string // The regex pattern that failed to match (if any)
}

// IsAllowed checks if the given tool name and arguments are permitted by policy.
//
// This is the primary authorization check called by the proxy for every
// tools/call request. The check flow is:
//
//  1. Check if tool is in allowed_tools list (O(1) lookup)
//  2. If tool has argument rules in tool_rules, validate each argument
//  3. Return detailed ValidationResult for error reporting
//
// Tool names are normalized to lowercase for case-insensitive matching.
//
// Authorization Logic:
//   - Tool not in allowed_tools → Deny
//   - Tool allowed, no argument rules → Allow (implicit allow all args)
//   - Tool allowed, has argument rules → Validate each constrained arg
//   - Any argument fails regex match → Deny with details
//
// Example:
//
//	result := engine.IsAllowed("fetch_url", map[string]any{"url": "https://evil.com"})
//	if !result.Allowed {
//	    // Return JSON-RPC Forbidden error with result.FailedArg
//	}
func (e *Engine) IsAllowed(toolName string, args map[string]any) ValidationResult {
	if e.allowedSet == nil {
		// No policy loaded = deny all (fail closed)
		return ValidationResult{Allowed: false}
	}

	// Normalize tool name for case-insensitive comparison
	normalized := strings.ToLower(strings.TrimSpace(toolName))

	// Step 1: Check if tool is in allowed list
	if _, allowed := e.allowedSet[normalized]; !allowed {
		return ValidationResult{Allowed: false}
	}

	// Step 2: Check for argument-level rules
	rule, hasRule := e.toolRules[normalized]
	if !hasRule || len(rule.compiledArgs) == 0 {
		// No argument rules = implicit allow all args
		return ValidationResult{Allowed: true}
	}

	// Step 3: Validate each constrained argument
	for argName, compiledRegex := range rule.compiledArgs {
		argValue, exists := args[argName]
		if !exists {
			// Argument not provided - this is a policy decision.
			// For security, we require constrained args to be present.
			return ValidationResult{
				Allowed:    false,
				FailedArg:  argName,
				FailedRule: rule.AllowArgs[argName],
			}
		}

		// Convert argument value to string for regex matching
		strValue := argToString(argValue)

		// Validate against the compiled regex
		if !compiledRegex.MatchString(strValue) {
			return ValidationResult{
				Allowed:    false,
				FailedArg:  argName,
				FailedRule: rule.AllowArgs[argName],
			}
		}
	}

	// All argument validations passed
	return ValidationResult{Allowed: true}
}

// argToString converts an argument value to string for regex matching.
// Handles common JSON types: string, number, bool.
func argToString(v any) string {
	switch val := v.(type) {
	case string:
		return val
	case float64:
		return fmt.Sprintf("%v", val)
	case int:
		return fmt.Sprintf("%d", val)
	case bool:
		return fmt.Sprintf("%t", val)
	default:
		return fmt.Sprintf("%v", val)
	}
}

// GetPolicyName returns the name of the loaded policy for logging.
func (e *Engine) GetPolicyName() string {
	if e.policy == nil {
		return "<no policy>"
	}
	return e.policy.Metadata.Name
}

// GetAllowedTools returns a copy of the allowed tools list for inspection.
func (e *Engine) GetAllowedTools() []string {
	if e.policy == nil {
		return nil
	}
	result := make([]string, len(e.policy.Spec.AllowedTools))
	copy(result, e.policy.Spec.AllowedTools)
	return result
}
