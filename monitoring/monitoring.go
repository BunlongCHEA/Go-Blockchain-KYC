package monitoring

import (
	"fmt"
	"log"
	"math/rand"
	"strings"
	"sync"
	"time"

	"Go-Blockchain-KYC/models"
)

// ==================== Types ====================

// AnomalyType represents different types of anomalies
type AnomalyType string

const (
	AnomalyHighFrequency      AnomalyType = "HIGH_FREQUENCY_ACCESS"
	AnomalyUnusualTime        AnomalyType = "UNUSUAL_ACCESS_TIME"
	AnomalyMultipleFailedAuth AnomalyType = "MULTIPLE_FAILED_AUTH"
	AnomalyBulkDataAccess     AnomalyType = "BULK_DATA_ACCESS"
	AnomalySuspiciousPattern  AnomalyType = "SUSPICIOUS_PATTERN"
	AnomalyGeoLocationChange  AnomalyType = "GEO_LOCATION_CHANGE"
	AnomalyUnauthorizedAccess AnomalyType = "UNAUTHORIZED_ACCESS"
)

// RiskLevel represents risk severity
type RiskLevel string

const (
	RiskLow      RiskLevel = "LOW"
	RiskMedium   RiskLevel = "MEDIUM"
	RiskHigh     RiskLevel = "HIGH"
	RiskCritical RiskLevel = "CRITICAL"
)

// AnomalyAlert represents a detected anomaly
type AnomalyAlert struct {
	ID          string                 `json:"id"`
	UserID      string                 `json:"user_id"`
	Type        AnomalyType            `json:"type"`
	RiskLevel   RiskLevel              `json:"risk_level"`
	Description string                 `json:"description"`
	Details     map[string]interface{} `json:"details"`
	IPAddress   string                 `json:"ip_address"`
	Timestamp   time.Time              `json:"timestamp"`
	IsReviewed  bool                   `json:"is_reviewed"`
	ReviewedBy  string                 `json:"reviewed_by"`
	ReviewedAt  *time.Time             `json:"reviewed_at"`
	ActionTaken string                 `json:"action_taken"`
}

// UserActivity represents user activity for monitoring
type UserActivity struct {
	UserID     string
	Action     string
	Resource   string
	ResourceID string
	IPAddress  string
	UserAgent  string
	Timestamp  time.Time
	Success    bool
	Details    map[string]interface{}
}

// UserActivityStats holds statistics for anomaly detection
type UserActivityStats struct {
	UserID            string
	RequestCount      int
	FailedAuthCount   int
	UniqueIPAddresses map[string]int
	AccessTimes       []time.Time
	ResourcesAccessed map[string]int
	LastActivity      time.Time
	SuspiciousScore   float64
}

// ==================== Storage Interface ====================

// StorageInterface defines what monitoring needs from storage (avoids import cycle)
type StorageInterface interface {
	SaveAuditLog(log *models.AuditLog) error
	BlockUser(userID, reason string) error
}

// ==================== Config ====================

// MonitoringConfig holds monitoring configuration
type MonitoringConfig struct {
	MaxRequestsPerMinute  int  `json:"max_requests_per_minute"`
	MaxFailedAuthAttempts int  `json:"max_failed_auth_attempts"`
	MaxUniqueIPsPerHour   int  `json:"max_unique_ips_per_hour"`
	BulkAccessThreshold   int  `json:"bulk_access_threshold"`
	ActivityWindowMinutes int  `json:"activity_window_minutes"`
	StatsResetHours       int  `json:"stats_reset_hours"`
	WorkingHoursStart     int  `json:"working_hours_start"`
	WorkingHoursEnd       int  `json:"working_hours_end"`
	AutoBlockOnCritical   bool `json:"auto_block_on_critical"`
	AlertRetentionDays    int  `json:"alert_retention_days"`
}

// DefaultMonitoringConfig returns default configuration
func DefaultMonitoringConfig() MonitoringConfig {
	return MonitoringConfig{
		MaxRequestsPerMinute:  100,
		MaxFailedAuthAttempts: 5,
		MaxUniqueIPsPerHour:   10,
		BulkAccessThreshold:   50,
		ActivityWindowMinutes: 5,
		StatsResetHours:       24,
		WorkingHoursStart:     8,
		WorkingHoursEnd:       18,
		AutoBlockOnCritical:   true,
		AlertRetentionDays:    90,
	}
}

// ==================== Monitoring Service ====================

// MonitoringService handles activity monitoring and anomaly detection
type MonitoringService struct {
	storage      StorageInterface
	userStats    map[string]*UserActivityStats
	alerts       []*AnomalyAlert
	mutex        sync.RWMutex
	config       MonitoringConfig
	alertChannel chan *AnomalyAlert
	stopChannel  chan struct{}
	rng          *rand.Rand
}

// NewMonitoringService creates a new monitoring service
func NewMonitoringService(storage StorageInterface, config MonitoringConfig) *MonitoringService {
	return &MonitoringService{
		storage:      storage,
		userStats:    make(map[string]*UserActivityStats),
		alerts:       make([]*AnomalyAlert, 0),
		config:       config,
		alertChannel: make(chan *AnomalyAlert, 100),
		stopChannel:  make(chan struct{}),
		rng:          rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Start starts the monitoring service
func (m *MonitoringService) Start() {
	go m.processAlerts()
	go m.periodicStatsReset()
	log.Println("   ✓ Monitoring service started")
	log.Println("   ✓ Anomaly detection enabled")
	log.Println("   ✓ Audit logging enabled")
}

// Stop stops the monitoring service
func (m *MonitoringService) Stop() {
	close(m.stopChannel)
	log.Println("Monitoring service stopped")
}

// RecordActivity records user activity and checks for anomalies
func (m *MonitoringService) RecordActivity(activity UserActivity) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Get or create user stats
	stats, exists := m.userStats[activity.UserID]
	if !exists {
		stats = &UserActivityStats{
			UserID:            activity.UserID,
			UniqueIPAddresses: make(map[string]int),
			AccessTimes:       make([]time.Time, 0),
			ResourcesAccessed: make(map[string]int),
		}
		m.userStats[activity.UserID] = stats
	}

	// Update stats
	stats.RequestCount++
	stats.LastActivity = activity.Timestamp
	stats.AccessTimes = append(stats.AccessTimes, activity.Timestamp)
	stats.UniqueIPAddresses[activity.IPAddress]++
	stats.ResourcesAccessed[activity.Resource]++

	// Track failed auth
	if !activity.Success && strings.Contains(strings.ToUpper(activity.Action), "LOGIN") {
		stats.FailedAuthCount++
	}

	// Record to audit log
	m.recordAuditLog(activity)

	// Check for anomalies
	m.detectAnomalies(activity, stats)
}

// recordAuditLog saves activity to audit_log table
func (m *MonitoringService) recordAuditLog(activity UserActivity) {
	if m.storage == nil {
		return
	}

	auditLog := &models.AuditLog{
		UserID:       activity.UserID,
		Action:       activity.Action,
		ResourceType: activity.Resource,
		ResourceID:   activity.ResourceID,
		Details:      activity.Details,
		IPAddress:    activity.IPAddress,
		UserAgent:    activity.UserAgent,
		CreatedAt:    activity.Timestamp,
	}

	if err := m.storage.SaveAuditLog(auditLog); err != nil {
		log.Printf("Failed to save audit log:  %v", err)
	}
}

// detectAnomalies checks for various anomaly patterns
func (m *MonitoringService) detectAnomalies(activity UserActivity, stats *UserActivityStats) {
	// Check high frequency access
	if m.checkHighFrequency(stats) {
		m.createAlert(activity, AnomalyHighFrequency, RiskMedium,
			"Unusually high request frequency detected",
			map[string]interface{}{
				"request_count": stats.RequestCount,
				"threshold":     m.config.MaxRequestsPerMinute,
			})
	}

	// Check multiple failed auth
	if stats.FailedAuthCount >= m.config.MaxFailedAuthAttempts {
		m.createAlert(activity, AnomalyMultipleFailedAuth, RiskHigh,
			"Multiple failed authentication attempts",
			map[string]interface{}{
				"failed_attempts": stats.FailedAuthCount,
				"threshold":       m.config.MaxFailedAuthAttempts,
			})
	}

	// Check unusual access time
	if m.checkUnusualTime(activity.Timestamp) {
		m.createAlert(activity, AnomalyUnusualTime, RiskLow,
			"Access outside normal working hours",
			map[string]interface{}{
				"access_time": activity.Timestamp.Format("15:04:05"),
				"working_hours": map[string]int{
					"start": m.config.WorkingHoursStart,
					"end":   m.config.WorkingHoursEnd,
				},
			})
	}

	// Check multiple IP addresses
	if len(stats.UniqueIPAddresses) > m.config.MaxUniqueIPsPerHour {
		m.createAlert(activity, AnomalyGeoLocationChange, RiskHigh,
			"Access from multiple IP addresses",
			map[string]interface{}{
				"unique_ips": len(stats.UniqueIPAddresses),
				"ip_list":    stats.UniqueIPAddresses,
				"threshold":  m.config.MaxUniqueIPsPerHour,
			})
	}

	// Check bulk data access
	if m.checkBulkAccess(stats) {
		m.createAlert(activity, AnomalyBulkDataAccess, RiskCritical,
			"Potential data exfiltration - bulk data access detected",
			map[string]interface{}{
				"resources_accessed": stats.ResourcesAccessed,
				"threshold":          m.config.BulkAccessThreshold,
			})
	}

	// Calculate suspicious score
	stats.SuspiciousScore = m.calculateSuspiciousScore(stats)

	if stats.SuspiciousScore >= 80 {
		m.createAlert(activity, AnomalySuspiciousPattern, RiskCritical,
			"High suspicious activity score",
			map[string]interface{}{
				"score": stats.SuspiciousScore,
			})
	}
}

// checkHighFrequency checks for high frequency requests
func (m *MonitoringService) checkHighFrequency(stats *UserActivityStats) bool {
	windowStart := time.Now().Add(-time.Duration(m.config.ActivityWindowMinutes) * time.Minute)

	recentCount := 0
	for _, t := range stats.AccessTimes {
		if t.After(windowStart) {
			recentCount++
		}
	}

	return recentCount > m.config.MaxRequestsPerMinute
}

// checkUnusualTime checks if access is outside working hours
func (m *MonitoringService) checkUnusualTime(timestamp time.Time) bool {
	hour := timestamp.Hour()
	return hour < m.config.WorkingHoursStart || hour > m.config.WorkingHoursEnd
}

// checkBulkAccess checks for bulk data access patterns
func (m *MonitoringService) checkBulkAccess(stats *UserActivityStats) bool {
	totalAccess := 0
	for _, count := range stats.ResourcesAccessed {
		totalAccess += count
	}
	return totalAccess > m.config.BulkAccessThreshold
}

// calculateSuspiciousScore calculates overall suspicious score
func (m *MonitoringService) calculateSuspiciousScore(stats *UserActivityStats) float64 {
	score := 0.0

	// Failed auth contributes to score
	if stats.FailedAuthCount > 0 {
		score += float64(stats.FailedAuthCount) * 10
	}

	// Multiple IPs contribute to score
	if len(stats.UniqueIPAddresses) > 3 {
		score += float64(len(stats.UniqueIPAddresses)) * 5
	}

	// High request count contributes to score
	if stats.RequestCount > m.config.MaxRequestsPerMinute/2 {
		score += 20
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}

// createAlert creates a new anomaly alert
func (m *MonitoringService) createAlert(activity UserActivity, anomalyType AnomalyType, riskLevel RiskLevel, description string, details map[string]interface{}) {
	alert := &AnomalyAlert{
		ID:          m.generateAlertID(),
		UserID:      activity.UserID,
		Type:        anomalyType,
		RiskLevel:   riskLevel,
		Description: description,
		Details:     details,
		IPAddress:   activity.IPAddress,
		Timestamp:   time.Now(),
		IsReviewed:  false,
	}

	m.alerts = append(m.alerts, alert)

	// Send to alert channel for processing
	select {
	case m.alertChannel <- alert:
	default:
		log.Println("Alert channel full, dropping alert")
	}

	// Auto-block on critical if enabled
	if m.config.AutoBlockOnCritical && riskLevel == RiskCritical {
		m.autoBlockUser(activity.UserID, alert)
	}

	// Save alert to audit log
	m.saveAlertToAuditLog(alert)
}

// saveAlertToAuditLog saves alert to audit_log table
func (m *MonitoringService) saveAlertToAuditLog(alert *AnomalyAlert) {
	if m.storage == nil {
		return
	}

	auditLog := &models.AuditLog{
		UserID:       alert.UserID,
		Action:       "ANOMALY_DETECTED",
		ResourceType: "SECURITY",
		ResourceID:   alert.ID,
		Details: map[string]interface{}{
			"alert_id":    alert.ID,
			"type":        alert.Type,
			"risk_level":  alert.RiskLevel,
			"description": alert.Description,
			"details":     alert.Details,
		},
		IPAddress: alert.IPAddress,
		CreatedAt: alert.Timestamp,
	}

	m.storage.SaveAuditLog(auditLog)
}

// autoBlockUser automatically blocks user on critical alerts
func (m *MonitoringService) autoBlockUser(userID string, alert *AnomalyAlert) {
	log.Printf("AUTO-BLOCK: User %s blocked due to %s", userID, alert.Type)

	if m.storage != nil {
		m.storage.BlockUser(userID, string(alert.Type))
	}

	alert.ActionTaken = "USER_AUTO_BLOCKED"
}

// processAlerts processes alerts asynchronously
func (m *MonitoringService) processAlerts() {
	for {
		select {
		case alert := <-m.alertChannel:
			m.handleAlert(alert)
		case <-m.stopChannel:
			return
		}
	}
}

// handleAlert handles individual alerts
func (m *MonitoringService) handleAlert(alert *AnomalyAlert) {
	log.Printf("ALERT [%s] User:  %s, Type: %s, Risk: %s - %s",
		alert.ID, alert.UserID, alert.Type, alert.RiskLevel, alert.Description)
}

// periodicStatsReset resets user stats periodically
func (m *MonitoringService) periodicStatsReset() {
	ticker := time.NewTicker(time.Duration(m.config.StatsResetHours) * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.mutex.Lock()
			m.userStats = make(map[string]*UserActivityStats)
			m.mutex.Unlock()
			log.Println("User activity stats reset")
		case <-m.stopChannel:
			return
		}
	}
}

// generateAlertID generates a unique alert ID
func (m *MonitoringService) generateAlertID() string {
	return fmt.Sprintf("ALT_%d_%d", time.Now().UnixNano(), m.rng.Intn(10000))
}

// ==================== Public Methods ====================

// GetAlerts returns all alerts with optional filters
func (m *MonitoringService) GetAlerts(userID string, riskLevel RiskLevel, reviewed *bool) []*AnomalyAlert {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	result := make([]*AnomalyAlert, 0)

	for _, alert := range m.alerts {
		if userID != "" && alert.UserID != userID {
			continue
		}
		if riskLevel != "" && alert.RiskLevel != riskLevel {
			continue
		}
		if reviewed != nil && alert.IsReviewed != *reviewed {
			continue
		}
		result = append(result, alert)
	}

	return result
}

// ReviewAlert marks an alert as reviewed
func (m *MonitoringService) ReviewAlert(alertID, reviewerID, action string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	for _, alert := range m.alerts {
		if alert.ID == alertID {
			now := time.Now()
			alert.IsReviewed = true
			alert.ReviewedBy = reviewerID
			alert.ReviewedAt = &now
			alert.ActionTaken = action
			return nil
		}
	}

	return fmt.Errorf("alert not found: %s", alertID)
}

// GetUserStats returns stats for a specific user
func (m *MonitoringService) GetUserStats(userID string) *UserActivityStats {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.userStats[userID]
}

// GetAllUserStats returns stats for all users
func (m *MonitoringService) GetAllUserStats() map[string]*UserActivityStats {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// Return a copy
	result := make(map[string]*UserActivityStats)
	for k, v := range m.userStats {
		result[k] = v
	}
	return result
}

// GetAlertCount returns count of alerts by risk level
func (m *MonitoringService) GetAlertCount() map[RiskLevel]int {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	counts := map[RiskLevel]int{
		RiskLow:      0,
		RiskMedium:   0,
		RiskHigh:     0,
		RiskCritical: 0,
	}

	for _, alert := range m.alerts {
		counts[alert.RiskLevel]++
	}

	return counts
}
