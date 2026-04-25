package models

// IntegrationKey represents an API key issued to an external integrator.
// Field names and JSON tags match the TypeScript IntegrationKey in db.ts exactly
// so the NextJS frontend can consume responses without transformation.
type IntegrationKey struct {
	ID                string         `json:"id"`
	Name              string         `json:"name"`
	Description       string         `json:"description"`
	Organization      string         `json:"organization"`
	KeyPrefix         string         `json:"key_prefix"`
	KeyHash           string         `json:"key_hash"`
	IsActive          bool           `json:"is_active"`
	IsDeleted         bool           `json:"is_deleted"`
	Scopes            []string       `json:"scopes"`
	CreatedAt         int64          `json:"created_at"`
	ExpiresAt         int64          `json:"expires_at"`
	LastUsedAt        int64          `json:"last_used_at"`
	RequestCount      int            `json:"request_count"`
	RequestCountToday int            `json:"request_count_today"`
	TodayDate         string         `json:"_today_date,omitempty"` // server-only; omitted in list responses
	ScopeCounts       map[string]int `json:"scope_counts"`
	ScopeCountsToday  map[string]int `json:"scope_counts_today"`
}
