package store

import "time"

// AlertSeverity defines threat level
type AlertSeverity string

const (
	SeverityLow      AlertSeverity = "low"
	SeverityMedium   AlertSeverity = "medium"
	SeverityHigh     AlertSeverity = "high"
	SeverityCritical AlertSeverity = "critical"
)

// Alert is a fully enriched security event persisted to the store
type Alert struct {
	ID           string        `json:"id"`
	RuleName     string        `json:"rule_name"`
	Severity     AlertSeverity `json:"severity"`
	Message      string        `json:"message"`
	Process      string        `json:"process"`
	Args         string        `json:"args"`
	Pod          string        `json:"pod"`
	Namespace    string        `json:"namespace"`
	ContainerID  string        `json:"container_id,omitempty"`
	Image        string        `json:"image,omitempty"`
	IP           string        `json:"ip,omitempty"`
	Port         int           `json:"port,omitempty"`
	PID          uint32        `json:"pid"`
	UID          uint32        `json:"uid"`
	ProcessTree  []string      `json:"process_tree,omitempty"`
	Acknowledged bool          `json:"acknowledged"`
	Killed       bool          `json:"killed"`
	Timestamp    time.Time     `json:"timestamp"`
	Node         string        `json:"node,omitempty"`
}

// AlertFilter is used by ListAlerts for server-side filtering
type AlertFilter struct {
	Severity         AlertSeverity `json:"severity,omitempty"`
	Namespace        string        `json:"namespace,omitempty"`
	Pod              string        `json:"pod,omitempty"`
	RuleName         string        `json:"rule_name,omitempty"`
	Process          string        `json:"process,omitempty"`
	Since            *time.Time    `json:"since,omitempty"`
	Until            *time.Time    `json:"until,omitempty"`
	Acknowledged     *bool         `json:"acknowledged,omitempty"`
	Limit            int           `json:"limit,omitempty"`
	Offset           int           `json:"offset,omitempty"`
}

// AlertPage is a paginated response
type AlertPage struct {
	Alerts []*Alert `json:"alerts"`
	Total  int      `json:"total"`
	Offset int      `json:"offset"`
	Limit  int      `json:"limit"`
}

// AlertStats holds aggregate counts for dashboard
type AlertStats struct {
	Total        int            `json:"total"`
	BySeverity   map[string]int `json:"by_severity"`
	Acknowledged int            `json:"acknowledged"`
	Killed       int            `json:"killed"`
	LastHour     int            `json:"last_hour"`
	Last24h      int            `json:"last_24h"`
}
