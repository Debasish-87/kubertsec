// pkg/rules/engine.go
// Production rule matching engine with regex support, compiled pattern cache,
// parent process matching, and namespace filtering.
package rules

import (
	"regexp"
	"strings"
	"sync"
)

// MatchContext carries all data needed to evaluate a rule.
type MatchContext struct {
	Process       string
	Args          string
	ParentProcess string
	Namespace     string
}

// compiledRule is a Rule with pre-compiled regex patterns.
type compiledRule struct {
	Rule
	processRe *regexp.Regexp
	argsRe    *regexp.Regexp
}

// Engine is a thread-safe, compiled rule matching engine.
type Engine struct {
	mu       sync.RWMutex
	compiled []compiledRule
	raw      *RuleSet
}

// NewEngine compiles a RuleSet into a fast matching engine.
func NewEngine(rs *RuleSet) (*Engine, error) {
	e := &Engine{raw: rs}
	if err := e.compile(rs); err != nil {
		return nil, err
	}
	return e, nil
}

// Reload atomically replaces the rule set. Safe to call at runtime.
func (e *Engine) Reload(rs *RuleSet) error {
	compiled, err := buildCompiled(rs)
	if err != nil {
		return err
	}
	e.mu.Lock()
	e.compiled = compiled
	e.raw = rs
	e.mu.Unlock()
	return nil
}

// RuleCount returns the number of enabled rules.
func (e *Engine) RuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.compiled)
}

// GetRules returns a copy of the raw rule set.
func (e *Engine) GetRules() []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.raw == nil {
		return nil
	}
	cp := make([]Rule, len(e.raw.Rules))
	copy(cp, e.raw.Rules)
	return cp
}

// Match returns the first rule that matches ctx, or nil.
func (e *Engine) Match(ctx MatchContext) *Rule {
	process := normalizeProcess(ctx.Process)
	args := strings.ToLower(strings.TrimSpace(ctx.Args))
	parent := strings.ToLower(strings.TrimSpace(ctx.ParentProcess))
	ns := strings.ToLower(strings.TrimSpace(ctx.Namespace))

	e.mu.RLock()
	defer e.mu.RUnlock()

	for i := range e.compiled {
		cr := &e.compiled[i]

		// Namespace whitelist
		if len(cr.Namespaces) > 0 && !containsStr(cr.Namespaces, ns) {
			continue
		}
		// Namespace blacklist
		if len(cr.ExcludeNamespaces) > 0 && containsStr(cr.ExcludeNamespaces, ns) {
			continue
		}

		// Parent process matching
		if cr.ParentProcess != "" {
			if parent != strings.ToLower(cr.ParentProcess) {
				continue
			}
		}
		if len(cr.ParentProcessAny) > 0 && !containsStr(cr.ParentProcessAny, parent) {
			continue
		}

		// Process matching — any of the three methods
		if !matchProcess(cr, process) {
			continue
		}

		// Args matching — all specified methods must pass
		if !matchArgs(cr, args) {
			continue
		}

		rule := cr.Rule
		return &rule
	}

	return nil
}

// MatchProcess is a convenience wrapper for callers without full context.
// Deprecated: prefer Match with MatchContext for full functionality.
func MatchProcess(rs *RuleSet, process, args string) *Rule {
	if rs == nil {
		return nil
	}
	e, err := NewEngine(rs)
	if err != nil {
		return nil
	}
	return e.Match(MatchContext{
		Process: process,
		Args:    args,
	})
}

// compile builds the compiled rule list (internal).
func (e *Engine) compile(rs *RuleSet) error {
	compiled, err := buildCompiled(rs)
	if err != nil {
		return err
	}
	e.compiled = compiled
	return nil
}

// buildCompiled compiles a RuleSet into []compiledRule, skipping disabled rules.
func buildCompiled(rs *RuleSet) ([]compiledRule, error) {
	if rs == nil {
		return nil, nil
	}

	out := make([]compiledRule, 0, len(rs.Rules))

	for _, r := range rs.Rules {
		if !r.IsEnabled() {
			continue
		}

		cr := compiledRule{Rule: r}

		if r.ProcessRegex != "" {
			re, err := regexp.Compile("(?i)" + r.ProcessRegex)
			if err != nil {
				return nil, err
			}
			cr.processRe = re
		}

		if r.ArgsRegex != "" {
			re, err := regexp.Compile("(?i)" + r.ArgsRegex)
			if err != nil {
				return nil, err
			}
			cr.argsRe = re
		}

		out = append(out, cr)
	}

	return out, nil
}

// matchProcess checks whether the process name satisfies the rule's process criteria.
func matchProcess(cr *compiledRule, process string) bool {
	// 1. Regex match
	if cr.processRe != nil {
		return cr.processRe.MatchString(process)
	}

	// 2. Exact list match
	if len(cr.Processes) > 0 {
		for _, p := range cr.Processes {
			if process == strings.ToLower(strings.TrimSpace(p)) {
				return true
			}
		}
		return false
	}

	// 3. Single process match (backward compatible)
	if cr.Process != "" {
		rp := strings.ToLower(strings.TrimSpace(cr.Process))
		return process == rp || strings.HasPrefix(process, rp)
	}

	// No process constraint = match all processes
	return true
}

// matchArgs checks whether the args string satisfies the rule's args criteria.
func matchArgs(cr *compiledRule, args string) bool {
	// Regex must pass if set
	if cr.argsRe != nil {
		if !cr.argsRe.MatchString(args) {
			return false
		}
	}

	// ArgsList: ALL must be present
	for _, a := range cr.ArgsList {
		if !strings.Contains(args, strings.ToLower(a)) {
			return false
		}
	}

	// ArgsAny: at least ONE must be present
	if len(cr.ArgsAny) > 0 {
		found := false
		for _, a := range cr.ArgsAny {
			if strings.Contains(args, strings.ToLower(a)) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Single Args substring
	if cr.Args != "" {
		if !strings.Contains(args, strings.ToLower(cr.Args)) {
			return false
		}
	}

	return true
}

// normalizeProcess cleans up a raw process comm string.
func normalizeProcess(process string) string {
	process = strings.TrimSpace(process)
	process = strings.ToLower(process)

	// runc:init-style suffix
	if idx := strings.Index(process, ":"); idx > 0 {
		process = process[:idx]
	}
	// kernel thread brackets [kworker/0:0]
	process = strings.Trim(process, "[]")

	// strip path prefix
	if idx := strings.LastIndex(process, "/"); idx >= 0 {
		process = process[idx+1:]
	}

	return process
}

// containsStr checks if needle is in haystack (case-insensitive).
func containsStr(haystack []string, needle string) bool {
	needle = strings.ToLower(strings.TrimSpace(needle))
	for _, h := range haystack {
		if strings.ToLower(strings.TrimSpace(h)) == needle {
			return true
		}
	}
	return false
}
