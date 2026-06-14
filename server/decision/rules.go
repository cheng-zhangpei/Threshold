package decision

import (
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

	// ===========================================================
	// R01: Device blacklisted
	// Highest priority: device is permanently blocked.
	// ===========================================================
	{ID: "R01_DEVICE_BLACKLISTED", Description: "device is blacklisted",
		Condition: func(ctx *types.ConnectionContext, _ []*types.ConnectionSummary, _ types.RiskLevel, ps *portrait.Store) bool {
			return ps.IsBlacklisted(ctx.DeviceUUID)
		}, Action: types.BLACKLIST_DEVICE},

	// ===========================================================
	// R02: Repeat offender
	// Last 3 connections all triggered alerts -> persistent threat.
	// ===========================================================
	{ID: "R02_REPEAT_OFFENDER", Description: "last 3 connections all triggered alerts",
		Condition: func(_ *types.ConnectionContext, history []*types.ConnectionSummary, _ types.RiskLevel, _ *portrait.Store) bool {
			if len(history) < 3 {
				return false
			}
			for _, s := range history[len(history)-3:] {
				if len(s.FlagsTriggered) == 0 {
					return false
				}
			}
			return true
		}, Action: types.BLACKLIST_DEVICE},

	// ===========================================================
	// R03: Historical heavy delete
	// Last 5 connections cumulative delete > 10 -> data destruction risk.
	// ===========================================================
	{ID: "R03_HISTORICAL_HEAVY_DELETE", Description: "last 5 connections cumulative delete > 10",
		Condition: func(_ *types.ConnectionContext, history []*types.ConnectionSummary, _ types.RiskLevel, _ *portrait.Store) bool {
			limit := 5
			if len(history) < limit {
				limit = len(history)
			}
			total := 0
			for _, s := range history[len(history)-limit:] {
				total += countDeletes(s.EventCounts)
			}
			return total > 10
		}, Action: types.BLACKLIST_DEVICE},

	// ===========================================================
	// R04: High portrait risk score
	// User profile risk score > 0.7 -> composite anomaly from history.
	// Aggregates alert frequency, write ratio, device count, off-hours.
	// ===========================================================
	{ID: "R04_PORTRAIT_HIGH_RISK", Description: "user portrait risk score > 0.7",
		Condition: func(ctx *types.ConnectionContext, _ []*types.ConnectionSummary, _ types.RiskLevel, ps *portrait.Store) bool {
			profile := ps.GetProfile(ctx.UserID)
			return profile.RiskScore() > 0.7
		}, Action: types.ALERT},

	// ===========================================================
	// R05: New device anomaly
	// Known user (>5 connections) using a never-seen device.
	// Possible credential theft or account sharing.
	// ===========================================================
	{ID: "R05_NEW_DEVICE_ANOMALY", Description: "established user on new device",
		Condition: func(ctx *types.ConnectionContext, _ []*types.ConnectionSummary, _ types.RiskLevel, ps *portrait.Store) bool {
			profile := ps.GetProfile(ctx.UserID)
			// User with >5 connections but this device is unknown
			if profile.TotalConnections <= 5 {
				return false
			}
			for _, d := range profile.KnownDevices {
				if d == ctx.DeviceUUID {
					return false
				}
			}
			return true
		}, Action: types.ALERT},

	// ===========================================================
	// R06: Historical heavy delete (current connection)
	// Current connection has 5+ delete ops -> active destruction.
	// ===========================================================
	{ID: "R06_BRUTE_FORCE_LOGIN", Description: "5+ login_failed in current connection",
		Condition: func(ctx *types.ConnectionContext, _ []*types.ConnectionSummary, _ types.RiskLevel, _ *portrait.Store) bool {
			return ctx.EventCounts()["login_failed"] >= 5
		}, Action: types.BLOCK_LOGIN},

	// ===========================================================
	// R07: Multiple delete events in single connection
	// 3+ delete ops in one session -> aggressive behavior.
	// ===========================================================
	{ID: "R07_BULK_DELETE", Description: "3+ delete ops in single connection",
		Condition: func(ctx *types.ConnectionContext, _ []*types.ConnectionSummary, _ types.RiskLevel, _ *portrait.Store) bool {
			return countDeletes(ctx.EventCounts()) >= 3
		}, Action: types.BLOCK_DEVICE},

	// ===========================================================
	// R08: Upload then start VM
	// Classic attack pattern: upload payload then execute.
	// ===========================================================
	{ID: "R08_UPLOAD_THEN_START", Description: "upload then start VM, suspicious payload",
		Condition: func(ctx *types.ConnectionContext, _ []*types.ConnectionSummary, _ types.RiskLevel, _ *portrait.Store) bool {
			hasUpload := false
			for _, e := range ctx.Events {
				if e.OpType == "image.upload" {
					hasUpload = true
				}
				if hasUpload && e.OpType == "vm.start" {
					return true
				}
			}
			return false
		}, Action: types.QUARANTINE_AND_ALERT},

	// ===========================================================
	// R09: Off-hours write
	// Write ops during 00:00-06:00 -> suspicious timing.
	// ===========================================================
	{ID: "R09_OFF_HOURS_WRITE", Description: "write ops during off-hours (0:00-6:00)",
		Condition: func(ctx *types.ConnectionContext, _ []*types.ConnectionSummary, _ types.RiskLevel, _ *portrait.Store) bool {
			for _, e := range ctx.Events {
				if !READ_OPS[e.OpType] && isOffHours(e.Timestamp) {
					return true
				}
			}
			return false
		}, Action: types.ALERT},

	// ===========================================================
	// R10: High write ratio
	// Current connection write ratio > 80%.
	// ===========================================================
	{ID: "R10_HIGH_WRITE_RATIO", Description: "write ratio > 80% in current connection",
		Condition: func(ctx *types.ConnectionContext, _ []*types.ConnectionSummary, _ types.RiskLevel, _ *portrait.Store) bool {
			return ctx.WriteRatio() > 0.8
		}, Action: types.ALERT},

	// ===========================================================
	// R99: Static risk fallback
	// Always true, handled by Engine as special case.
	// ===========================================================
	{ID: "R99_STATIC_RISK", Description: "fallback: static risk level",
		Condition: func(_ *types.ConnectionContext, _ []*types.ConnectionSummary, _ types.RiskLevel, _ *portrait.Store) bool {
			return true
		}, Action: types.ALLOW},
}