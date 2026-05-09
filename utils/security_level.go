package utils

func ActionSecurityLevel(action string) *int {
	priority := map[string]int{
		// ── A ───────────────────────────────────────────────────────
		"ANOMALY_DETECTED": 0, // Critical
		"AUDIT_LOG_READ":   3, // Low

		// ── B ───────────────────────────────────────────────────────
		"BANK_CREATED":          2, // Medium
		"BANK_DEACTIVATED":      1, // High
		"BANK_READ":             3, // Low
		"BANK_UPDATED":          2, // Medium
		"BLOCK_LIST_READ":       3, // Low
		"BLOCK_MINED":           2, // Medium
		"BLOCK_READ":            3, // Low
		"BLOCKCHAIN_STATS_READ": 3, // Low

		// ── C ───────────────────────────────────────────────────────
		"CERTIFICATE_ISSUED":        1, // High
		"CERTIFICATE_LIST":          3, // Low
		"CERTIFICATE_VERIFIED":      2, // Medium
		"CERTIFICATE_VERIFY_FAILED": 1, // High
		"CHAIN_VALIDATED":           3, // Low

		// ── E ───────────────────────────────────────────────────────
		"EMERGENCY_LOCK_DISABLED": 0, // Critical
		"EMERGENCY_LOCK_ENABLED":  0, // Critical

		// ── I ───────────────────────────────────────────────────────
		"INTEGRATION_KEY_DELETED":  1, // High
		"INTEGRATION_KEY_UPSERTED": 2, // Medium
		"INTEGRATION_KEYS_SYNCED":  3, // Low

		// ── K ───────────────────────────────────────────────────────
		"KEK_REWRAP_COMPLETED": 1, // High
		"KEK_ROTATED":          0, // Critical
		"KYC_AI_SCAN":          2, // Medium
		"KYC_AUTO_VERIFIED":    2, // Medium
		"KYC_CREATED":          2, // Medium
		"KYC_DELETED":          0, // Critical
		"KYC_DOC_UPLOADED":     2, // Medium
		"KYC_LIST":             3, // Low
		"KYC_PERIODIC_REVIEW":  1, // High
		"KYC_READ":             3, // Low
		"KYC_REJECTED":         1, // High
		"KYC_SELFIE_UPLOADED":  2, // Medium
		"KYC_UPDATED":          2, // Medium
		"KYC_VERIFIED":         1, // High

		// ── L ───────────────────────────────────────────────────────
		"LOGIN":                        1, // High
		"LOGIN_BLOCKED_EMERGENCY_LOCK": 0, // Critical
		"LOGIN_FAILED":                 0, // Critical
		"LOGOUT":                       3, // Low

		// ── P ───────────────────────────────────────────────────────
		"PASSWORD_CHANGED":         1, // High
		"PASSWORD_EXPIRED":         1, // High
		"PASSWORD_FORCE_RESET_ALL": 0, // Critical
		"PASSWORD_POLICY_READ":     3, // Low
		"PASSWORD_POLICY_UPDATED":  1, // High
		"PENDING_TX_READ":          3, // Low

		// ── R ───────────────────────────────────────────────────────
		"REGISTER":                    1, // High
		"RENEWAL_ALERT_CONFIGURED":    2, // Medium
		"RENEWAL_ALERT_READ":          3, // Low
		"RENEWAL_ALERT_SENT_MANUAL":   2, // Medium
		"RENEWAL_ALERT_TOGGLED":       3, // Low
		"REQUESTER_KEY_READ":          3, // Low
		"REQUESTER_KEY_REVOKED":       0, // Critical
		"REQUESTER_KEYPAIR_GENERATED": 1, // High

		// ── S ───────────────────────────────────────────────────────
		"SECURITY_ALERT_READ":     3, // Low
		"SECURITY_ALERT_REVIEWED": 1, // High
		"SIGNING_KEY_ROTATED":     0, // Critical

		// ── T ───────────────────────────────────────────────────────
		"TOKEN_REFRESH": 3, // Low

		// ── U ───────────────────────────────────────────────────────
		"USER_BLOCKED":        0, // Critical
		"USER_CREATED":        1, // High
		"USER_DELETED":        0, // Critical
		"USER_PASSWORD_RESET": 1, // High
		"USER_UNBLOCKED":      1, // High
		"USER_UPDATED":        2, // Medium
	}

	p, ok := priority[action]
	if !ok {
		p = 3 // default → Low for unknown actions
	}
	level := p
	return &level
}
