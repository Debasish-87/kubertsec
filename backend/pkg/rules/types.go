package rules

type Rule struct {
	Name              string   `yaml:"name"                        json:"name"`
	Enabled           *bool    `yaml:"enabled,omitempty"           json:"enabled,omitempty"`
	Process           string   `yaml:"process,omitempty"           json:"process,omitempty"`
	Processes         []string `yaml:"processes,omitempty"         json:"processes,omitempty"`
	ProcessRegex      string   `yaml:"process_regex,omitempty"     json:"process_regex,omitempty"`
	Args              string   `yaml:"args,omitempty"              json:"args,omitempty"`
	ArgsRegex         string   `yaml:"args_regex,omitempty"        json:"args_regex,omitempty"`
	ArgsList          []string `yaml:"args_list,omitempty"         json:"args_list,omitempty"`
	ArgsAny           []string `yaml:"args_any,omitempty"          json:"args_any,omitempty"`
	ParentProcess     string   `yaml:"parent_process,omitempty"    json:"parent_process,omitempty"`
	ParentProcessAny  []string `yaml:"parent_process_any,omitempty" json:"parent_process_any,omitempty"`
	Namespaces        []string `yaml:"namespaces,omitempty"        json:"namespaces,omitempty"`
	ExcludeNamespaces []string `yaml:"exclude_namespaces,omitempty" json:"exclude_namespaces,omitempty"`
	Severity          string   `yaml:"severity"                    json:"severity"`
	Message           string   `yaml:"message"                     json:"message"`
	Tags              []string `yaml:"tags,omitempty"              json:"tags,omitempty"`
	Mode              string   `yaml:"mode,omitempty"              json:"mode,omitempty"`
}

func (r *Rule) IsEnabled() bool {
	if r.Enabled == nil {
		return true
	}
	return *r.Enabled
}

type RuleSet struct {
	Rules []Rule `yaml:"rules"`
}
