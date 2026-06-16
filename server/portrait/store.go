package portrait

import (
	"Threshold/pkg/types"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"Threshold/pkg/storage"
	_ "Threshold/pkg/types"
)

const MaxHistoryPerUser = 50

// ============================================================
// UserProfile 用户聚合画像
// 每次连接关闭时增量更新，用于决策引擎的跨连接判断
// ============================================================
type UserProfile struct {
	UserID           string    `json:"user_id"`
	TotalConnections int       `json:"total_connections"`
	UniqueDevices    int       `json:"unique_devices"`
	UniqueIPs        int       `json:"unique_ips"`
	TotalWriteOps    int       `json:"total_write_ops"`
	TotalEvents      int       `json:"total_events"`
	AlertCount       int       `json:"alert_count"`
	OffHoursCount    int       `json:"off_hours_count"`
	KnownDevices     []string  `json:"known_devices"`
	KnownIPs         []string  `json:"known_ips"`
	FirstSeenAt      time.Time `json:"first_seen_at"`
	LastSeenAt       time.Time `json:"last_seen_at"`
}

// RiskScore returns a composite risk score (0.0-1.0) based on portrait.
func (p *UserProfile) RiskScore() float64 {
	if p.TotalConnections == 0 {
		return 0.0
	}
	score := 0.0
	// Alert ratio: higher = riskier
	alertRatio := float64(p.AlertCount) / float64(p.TotalConnections)
	score += alertRatio * 0.4
	// Write ratio: higher = riskier
	if p.TotalEvents > 0 {
		writeRatio := float64(p.TotalWriteOps) / float64(p.TotalEvents)
		score += writeRatio * 0.2
	}
	// Device diversity: more devices = higher risk
	if p.UniqueDevices > 3 {
		score += 0.2
	} else if p.UniqueDevices > 1 {
		score += 0.1
	}
	// Off hours ratio
	offRatio := float64(p.OffHoursCount) / float64(p.TotalConnections)
	score += offRatio * 0.2

	if score > 1.0 {
		score = 1.0
	}
	return score
}

// ============================================================
// Store
// ============================================================
type Store struct {
	store storage.Store
}

func NewStore(store storage.Store) *Store {
	return &Store{store: store}
}

// ============================================================
// Blacklist
// ============================================================
func (s *Store) IsBlacklisted(deviceUUID string) bool {
	val := false
	s.store.View(func(tx storage.Tx) error {
		v, err := tx.Get(storage.BucketBlacklist, []byte(deviceUUID))
		if err == nil && v != nil {
			val = true
		}
		return nil
	})
	return val
}

func (s *Store) BlacklistDevice(deviceUUID string, reason string) error {
	return s.store.Update(func(tx storage.Tx) error {
		return tx.Put(storage.BucketBlacklist, []byte(deviceUUID), []byte(reason))
	})
}

// ============================================================
// ConnectionSummary persistence
// key format: userID + | + timestamp (lexicographic sort = chronological)
// ============================================================
func summaryKey(userID string, t time.Time) []byte {
	return []byte(userID + "|" + t.Format(time.RFC3339Nano))
}

func summaryPrefix(userID string) []byte {
	return []byte(userID + "|")
}

func (s *Store) AppendSummary(userID string, summary *types.ConnectionSummary) error {
	return s.store.Update(func(tx storage.Tx) error {
		data, err := json.Marshal(summary)
		if err != nil {
			return fmt.Errorf("marshal summary: %w", err)
		}
		key := summaryKey(userID, summary.ConnectedAt)
		if err := tx.Put(storage.BucketPortraits, key, data); err != nil {
			return err
		}
		// Trim: keep only last MaxHistoryPerUser entries
		return s.trimHistory(tx, userID)
	})
}

func (s *Store) trimHistory(tx storage.Tx, userID string) error {
	keys, _, err := tx.PrefixScan(storage.BucketPortraits, summaryPrefix(userID))
	if err != nil {
		return err
	}
	if len(keys) <= MaxHistoryPerUser {
		return nil
	}
	// keys are sorted chronologically, delete oldest
	toDelete := len(keys) - MaxHistoryPerUser
	for i := 0; i < toDelete; i++ {
		if err := tx.Delete(storage.BucketPortraits, keys[i]); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) GetHistory(userID string, limit int) []*types.ConnectionSummary {
	var result []*types.ConnectionSummary
	s.store.View(func(tx storage.Tx) error {
		keys, values, err := tx.PrefixScan(storage.BucketPortraits, summaryPrefix(userID))
		if err != nil {
			return err
		}
		// Return last N (most recent)
		start := 0
		if len(keys) > limit {
			start = len(keys) - limit
		}
		for i := start; i < len(keys); i++ {
			var s types.ConnectionSummary
			if err := json.Unmarshal(values[i], &s); err == nil {
				result = append(result, &s)
			}
		}
		return nil
	})
	return result
}

// ============================================================
// UserProfile persistence
// ============================================================
func (s *Store) GetProfile(userID string) *UserProfile {
	var p UserProfile
	s.store.View(func(tx storage.Tx) error {
		v, err := tx.Get(storage.BucketProfiles, []byte(userID))
		if err != nil || v == nil {
			return nil
		}
		return json.Unmarshal(v, &p)
	})
	return &p
}

func (s *Store) UpsertProfile(p *UserProfile) error {
	return s.store.Update(func(tx storage.Tx) error {
		data, err := json.Marshal(p)
		if err != nil {
			return fmt.Errorf("marshal profile: %w", err)
		}
		return tx.Put(storage.BucketProfiles, []byte(p.UserID), data)
	})
}

// ============================================================
// OnConnectionClose extracts summary + updates profile
// This is the main entry point called by Handler.CloseConnection
// ============================================================
func (s *Store) OnConnectionClose(ctx *types.ConnectionContext) error {
	// 1. Extract ConnectionSummary from ConnectionContext
	summary := s.extractSummary(ctx)

	// 2. Append summary to history
	if err := s.AppendSummary(ctx.UserID, summary); err != nil {
		return fmt.Errorf("append summary: %w", err)
	}

	// 3. Update UserProfile
	return s.updateProfile(ctx, summary)
}

func (s *Store) extractSummary(ctx *types.ConnectionContext) *types.ConnectionSummary {
	eventCounts := ctx.EventCounts()
	writeRatio := ctx.WriteRatio()
	totalEvents := len(ctx.Events)

	writeOps := 0
	for op, cnt := range eventCounts {
		if !strings.HasPrefix(strings.TrimSpace(op), "GET ") {
			writeOps += cnt
		}
	}

	offHoursWrites := 0
	for _, e := range ctx.Events {
		hour := e.Timestamp.Hour()
		if hour >= 0 && hour < 6 && !strings.HasPrefix(strings.TrimSpace(e.OpType), "GET ") {
			offHoursWrites++
		}
	}

	return &types.ConnectionSummary{
		ConnectionID:   ctx.ConnectionID,
		UserID:         ctx.UserID,
		DeviceUUID:     ctx.DeviceUUID,
		ConnectedAt:    ctx.ConnectedAt,
		EndedAt:        time.Now(),
		DurationSec:    time.Since(ctx.ConnectedAt).Seconds(),
		IP:             ctx.IP,
		EventCounts:    eventCounts,
		FlagsTriggered: ctx.TriggeredFlags,
		OffHoursWrites: offHoursWrites,
		TotalEvents:    totalEvents,
		WriteRatio:     writeRatio,
	}
}

func (s *Store) updateProfile(ctx *types.ConnectionContext, summary *types.ConnectionSummary) error {
	p := s.GetProfile(ctx.UserID)
	if p.UserID == "" {
		p = &UserProfile{UserID: ctx.UserID, FirstSeenAt: ctx.ConnectedAt}
	}

	p.TotalConnections++
	p.TotalEvents += summary.TotalEvents
	p.TotalWriteOps += summary.TotalEvents - len(summary.EventCounts) + countWriteOps(summary.EventCounts)
	p.LastSeenAt = summary.EndedAt

	if len(summary.FlagsTriggered) > 0 {
		p.AlertCount++
	}
	if summary.OffHoursWrites > 0 {
		p.OffHoursCount++
	}

	// Track unique devices
	if !containsStr(p.KnownDevices, ctx.DeviceUUID) {
		p.KnownDevices = append(p.KnownDevices, ctx.DeviceUUID)
		p.UniqueDevices = len(p.KnownDevices)
	}
	// Track unique IPs
	if !containsStr(p.KnownIPs, ctx.IP) {
		p.KnownIPs = append(p.KnownIPs, ctx.IP)
		p.UniqueIPs = len(p.KnownIPs)
	}

	return s.UpsertProfile(p)
}

func countWriteOps(eventCounts map[string]int) int {
	n := 0
	for op, cnt := range eventCounts {
		if !strings.HasPrefix(strings.TrimSpace(op), "GET ") {
			n += cnt
		}
	}
	return n
}

func containsStr(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
