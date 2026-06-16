package decision

import (
	"log"
	"strings"
	"time"

	"Threshold/pkg/types"
	"Threshold/server/portrait"
)

type RuleFunc func(ctx *types.ConnectionContext, history []*types.ConnectionSummary, riskLevel types.RiskLevel, ps *portrait.Store) bool

type Rule struct {
	ID          string
	Description string
	Condition   RuleFunc
	Action      types.Action
}

func isOffHours(t time.Time) bool {
	return t.Hour() >= 0 && t.Hour() < 6
}

func isDeleteOp(op string) bool {
	return strings.Contains(op, ".delete")
}

func countDeletes(eventCounts map[string]int) int {
	total := 0
	for op, cnt := range eventCounts {
		if isDeleteOp(op) {
			total += cnt
		}
	}
	return total
}

// DECISION_RULES rules ordered by severity (highest first).
// Engine evaluates in order, first match wins.
var DECISION_RULES = []Rule{

	// R01: Device blacklisted
	{ID: "R01_DEVICE_BLACKLISTED", Description: "device is blacklisted",
		Condition: func(ctx *types.ConnectionContext, _ []*types.ConnectionSummary, _ types.RiskLevel, ps *portrait.Store) bool {
			if ps.IsBlacklisted(ctx.DeviceUUID) {
				log.Printf("[RULE] %s | user=%s device=%s conn=%s | device is blacklisted",
					"R01", ctx.UserID, ctx.DeviceUUID, ctx.ConnectionID)
				return true
			}
			return false
		}, Action: types.BLACKLIST_DEVICE},

	// R02: Repeat offender
	{ID: "R02_REPEAT_OFFENDER", Description: "last 3 connections all triggered alerts",
		Condition: func(ctx *types.ConnectionContext, history []*types.ConnectionSummary, _ types.RiskLevel, _ *portrait.Store) bool {
			if len(history) < 3 {
				return false
			}
			for _, s := range history[len(history)-3:] {
				if len(s.FlagsTriggered) == 0 {
					return false
				}
			}
			log.Printf("[RULE] %s | user=%s device=%s conn=%s | last 3 connections all triggered alerts",
				"R02", ctx.UserID, ctx.DeviceUUID, ctx.ConnectionID)
			return true
		}, Action: types.BLACKLIST_DEVICE},

	// R03: Historical heavy delete
	{ID: "R03_HISTORICAL_HEAVY_DELETE", Description: "last 5 connections cumulative delete > 10",
		Condition: func(ctx *types.ConnectionContext, history []*types.ConnectionSummary, _ types.RiskLevel, _ *portrait.Store) bool {
			limit := 5
			if len(history) < limit {
				limit = len(history)
			}
			total := 0
			for _, s := range history[len(history)-limit:] {
				total += countDeletes(s.EventCounts)
			}
			if total > 10 {
				log.Printf("[RULE] %s | user=%s device=%s conn=%s | last %d connections cumulative delete=%d",
					"R03", ctx.UserID, ctx.DeviceUUID, ctx.ConnectionID, limit, total)
				return true
			}
			return false
		}, Action: types.BLACKLIST_DEVICE},

	// R04: High portrait risk score
	{ID: "R04_PORTRAIT_HIGH_RISK", Description: "user portrait risk score > 0.7",
		Condition: func(ctx *types.ConnectionContext, _ []*types.ConnectionSummary, _ types.RiskLevel, ps *portrait.Store) bool {
			profile := ps.GetProfile(ctx.UserID)
			score := profile.RiskScore()
			if score > 0.7 {
				log.Printf("[RULE] %s | user=%s device=%s conn=%s | risk_score=%.3f",
					"R04", ctx.UserID, ctx.DeviceUUID, ctx.ConnectionID, score)
				return true
			}
			return false
		}, Action: types.ALERT},

	// R05: New device anomaly
	{ID: "R05_NEW_DEVICE_ANOMALY", Description: "established user on new device",
		Condition: func(ctx *types.ConnectionContext, _ []*types.ConnectionSummary, _ types.RiskLevel, ps *portrait.Store) bool {
			profile := ps.GetProfile(ctx.UserID)
			if profile.TotalConnections <= 5 {
				return false
			}
			for _, d := range profile.KnownDevices {
				if d == ctx.DeviceUUID {
					return false
				}
			}
			log.Printf("[RULE] %s | user=%s device=%s conn=%s | established user(total_conn=%d) on new device",
				"R05", ctx.UserID, ctx.DeviceUUID, ctx.ConnectionID, profile.TotalConnections)
			return true
		}, Action: types.ALERT},

	// R06: Brute force login
	{ID: "R06_BRUTE_FORCE_LOGIN", Description: "5+ login_failed in current connection",
		Condition: func(ctx *types.ConnectionContext, _ []*types.ConnectionSummary, _ types.RiskLevel, _ *portrait.Store) bool {
			count := ctx.EventCounts()["login_failed"]
			if count >= 5 {
				log.Printf("[RULE] %s | user=%s device=%s conn=%s | login_failed count=%d",
					"R06", ctx.UserID, ctx.DeviceUUID, ctx.ConnectionID, count)
				return true
			}
			return false
		}, Action: types.BLOCK_LOGIN},

	// R07: Bulk delete
	{ID: "R07_BULK_DELETE", Description: "3+ delete ops in single connection",
		Condition: func(ctx *types.ConnectionContext, _ []*types.ConnectionSummary, _ types.RiskLevel, _ *portrait.Store) bool {
			total := countDeletes(ctx.EventCounts())
			if total >= 3 {
				log.Printf("[RULE] %s | user=%s device=%s conn=%s | delete_count=%d",
					"R07", ctx.UserID, ctx.DeviceUUID, ctx.ConnectionID, total)
				return true
			}
			return false
		}, Action: types.BLOCK_DEVICE},

	// R08: Upload then start VM
	{ID: "R08_UPLOAD_THEN_START", Description: "upload then start VM, suspicious payload",
		Condition: func(ctx *types.ConnectionContext, _ []*types.ConnectionSummary, _ types.RiskLevel, _ *portrait.Store) bool {
			hasUpload := false
			for _, e := range ctx.Events {
				if e.OpType == "image.upload" {
					hasUpload = true
				}
				if hasUpload && e.OpType == "vm.start" {
					log.Printf("[RULE] %s | user=%s device=%s conn=%s | detected upload->vm.start sequence",
						"R08", ctx.UserID, ctx.DeviceUUID, ctx.ConnectionID)
					return true
				}
			}
			return false
		}, Action: types.QUARANTINE_AND_ALERT},

	// R09: Off-hours write
	{ID: "R09_OFF_HOURS_WRITE", Description: "write ops during off-hours (0:00-6:00)",
		Condition: func(ctx *types.ConnectionContext, _ []*types.ConnectionSummary, _ types.RiskLevel, _ *portrait.Store) bool {
			for _, e := range ctx.Events {
				if !READ_OPS[e.OpType] && isOffHours(e.Timestamp) {
					log.Printf("[RULE] %s | user=%s device=%s conn=%s | write op=%s at off-hours %s",
						"R09", ctx.UserID, ctx.DeviceUUID, ctx.ConnectionID, e.OpType, e.Timestamp.Format("15:04"))
					return true
				}
			}
			return false
		}, Action: types.ALERT},

	// R10: High write ratio
	{ID: "R10_HIGH_WRITE_RATIO", Description: "write ratio > 80% in current connection",
		Condition: func(ctx *types.ConnectionContext, _ []*types.ConnectionSummary, _ types.RiskLevel, _ *portrait.Store) bool {
			ratio := ctx.WriteRatio()
			if ratio > 0.8 {
				log.Printf("[RULE] %s | user=%s device=%s conn=%s | write_ratio=%.1f%%",
					"R10", ctx.UserID, ctx.DeviceUUID, ctx.ConnectionID, ratio*100)
				return true
			}
			return false
		}, Action: types.ALERT},

	// R99: Static risk fallback
	{ID: "R99_STATIC_RISK", Description: "fallback: static risk level",
		Condition: func(_ *types.ConnectionContext, _ []*types.ConnectionSummary, _ types.RiskLevel, _ *portrait.Store) bool {
			return true
		}, Action: types.ALLOW},
}
