package models

import "time"

// SecurityLevel maps to the security_status table.
// 0=Critical  1=High  2=Medium  3=Low  (nil = unknown / legacy)
type SecurityLevel *int

// AuditLog represents an audit log entry (shared between packages)
type AuditLog struct {
	ID            int64                  `json:"id"`
	UserID        string                 `json:"user_id"`
	Action        string                 `json:"action"`
	ResourceType  string                 `json:"resource_type"`
	ResourceID    string                 `json:"resource_id"`
	Details       map[string]interface{} `json:"details"`
	IPAddress     string                 `json:"ip_address"`
	UserAgent     string                 `json:"user_agent"`
	CreatedAt     time.Time              `json:"created_at"`
	SecurityLevel *int                   `json:"security_level,omitempty"`
}
