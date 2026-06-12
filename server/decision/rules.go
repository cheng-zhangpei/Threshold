package decision

import (
	"time"

	"Threshold/pkg/types"
	"Threshold/server/portrait"
)

// RuleFunc 是所有决策规则的条件函数签名。
// 接收当前连接上下文、历史连接摘要、风险等级和画像存储，返回是否命中该规则。
type RuleFunc func(ctx *types.ConnectionContext, history []*types.ConnectionSummary, riskLevel types.RiskLevel, ps *portrait.Store) bool

// Rule 表示一条决策规则。
// Condition 命中后，Engine 将执行对应的 Action。
type Rule struct {
	ID          string
	Description string
	Condition   RuleFunc
	Action      types.Action
}

// isOffHours 判断给定时间是否处于凌晨离线时段（00:00 ~ 06:00）。
// 该时段内的写操作通常被视为异常行为。
func isOffHours(t time.Time) bool {
	hour := t.Hour()
	return hour >= 0 && hour < 6
}

// DECISION_RULES 是按优先级排列的规则列表。
// Engine 按顺序遍历，第一个命中的规则将决定最终动作。
// 规则优先级：黑名单 > 历史恶意行为 > 行为异常检测 > 风险等级兜底。
var DECISION_RULES = []Rule{

	// ────────────────────────────────────────────
	// R01: 设备黑名单
	// 如果当前设备 UUID 已被加入画像黑名单，则直接封禁设备。
	// 这是最高优先级规则，无论其他上下文如何都会执行。
	// ────────────────────────────────────────────
	{ID: "R01_DEVICE_BLACKLISTED", Description: "device is blacklisted",
		Condition: func(ctx *types.ConnectionContext, _ []*types.ConnectionSummary, _ types.RiskLevel, ps *portrait.Store) bool {
			return ps.IsBlacklisted(ctx.DeviceUUID)
		}, Action: types.BLACKLIST_DEVICE},

	// ────────────────────────────────────────────
	// R02: 连续违规
	// 最近 3 次连接均触发过告警标记，说明该设备存在持续性恶意行为。
	// 任一次连接没有任何标记则不命中，给偶发情况留有余地。
	// ────────────────────────────────────────────
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

	// ────────────────────────────────────────────
	// R03: 历史累积大量删除
	// 统计最近 5 次连接 + 当前连接中的所有删除类操作。
	// 删除操作包括：image.delete、image.delete_private_cloud、
	// image.delete_private_all、image.delete_local。
	// 累计超过 10 次视为异常数据销毁行为，封禁设备。
	// ────────────────────────────────────────────
	{ID: "R03_HISTORICAL_HEAVY_DELETE", Description: "last 5 connections cumulative delete > 10",
		Condition: func(ctx *types.ConnectionContext, history []*types.ConnectionSummary, _ types.RiskLevel, _ *portrait.Store) bool {
			limit := 5
			if len(history) < limit {
				limit = len(history)
			}
			total := 0
			for _, s := range history[len(history)-limit:] {
				for _, k := range []string{"image.delete", "image.delete_private_cloud", "image.delete_private_all", "image.delete_local"} {
					total += s.EventCounts[k]
				}
			}
			// 将当前连接的删除事件也纳入统计
			for _, k := range []string{"image.delete", "image.delete_private_cloud", "image.delete_private_all", "image.delete_local"} {
				total += ctx.EventCounts()[k]
			}
			return total > 10
		}, Action: types.BLACKLIST_DEVICE},

	// ────────────────────────────────────────────
	// R04: 曾被标记为黑名单
	// 历史连接中只要出现过 BLACKLIST_DEVICE 标记，即使当前已解除黑名单，
	// 仍然要求二次验证（2FA），防止攻击者绕过后再次接入。
	// ────────────────────────────────────────────
	{ID: "R04_HISTORICAL_BLACKLISTED", Description: "previously blacklisted, require 2FA",
		Condition: func(_ *types.ConnectionContext, history []*types.ConnectionSummary, _ types.RiskLevel, _ *portrait.Store) bool {
			for _, s := range history {
				for _, f := range s.FlagsTriggered {
					if f == "BLACKLIST_DEVICE" {
						return true
					}
				}
			}
			return false
		}, Action: types.REQUIRE_2FA},

	// ────────────────────────────────────────────
	// R05: IP 跳跃
	// 最近 5 次连接 + 当前连接使用了 3 个以上不同 IP 地址。
	// 频繁更换 IP 可能意味着使用代理/VPN 绕过地域限制，
	// 或账号在多个地理位置被共享使用，需要二次验证确认身份。
	// ────────────────────────────────────────────
	{ID: "R05_IP_HOPPING", Description: "last 5 connections from 3+ different IPs",
		Condition: func(ctx *types.ConnectionContext, history []*types.ConnectionSummary, _ types.RiskLevel, _ *portrait.Store) bool {
			limit := 5
			if len(history) < limit {
				limit = len(history)
			}
			ips := make(map[string]bool)
			for _, s := range history[len(history)-limit:] {
				ips[s.IP] = true
			}
			ips[ctx.IP] = true
			return len(ips) > 3
		}, Action: types.REQUIRE_2FA},

	// ────────────────────────────────────────────
	// R06: 暴力破解登录
	// 当前连接中 login_failed 事件超过 5 次，
	// 判定为暴力破解尝试，立即阻止登录。
	// ────────────────────────────────────────────
	{ID: "R06_BRUTE_FORCE_LOGIN", Description: "brute force login failed > 5",
		Condition: func(ctx *types.ConnectionContext, _ []*types.ConnectionSummary, _ types.RiskLevel, _ *portrait.Store) bool {
			count := 0
			for _, e := range ctx.Events {
				if e.OpType == "login_failed" {
					count++
				}
			}
			return count > 5
		}, Action: types.BLOCK_LOGIN},

	// ────────────────────────────────────────────
	// R07: 单次连接批量删除
	// 当前连接中删除操作超过 3 次。
	// 与 R03 不同，这里只看当前连接的瞬时行为，
	// 不依赖历史数据，用于快速拦截即时的批量删除。
	// ────────────────────────────────────────────
	{ID: "R07_BULK_DELETE", Description: "bulk delete > 3 in current connection",
		Condition: func(ctx *types.ConnectionContext, _ []*types.ConnectionSummary, _ types.RiskLevel, _ *portrait.Store) bool {
			total := 0
			for _, k := range []string{"image.delete", "image.delete_private_cloud", "image.delete_private_all", "image.delete_local"} {
				total += ctx.EventCounts()[k]
			}
			return total > 3
		}, Action: types.BLOCK_DEVICE},

	// ────────────────────────────────────────────
	// R08: 上传后启动虚拟机
	// 检测到先上传镜像、再启动虚拟机的操作序列。
	// 这是典型的恶意载荷投递模式：攻击者上传恶意镜像后
	// 立即启动 VM 执行，需要隔离连接并触发告警。
	// 注意：只检测 upload 在前、vm.start 在后的顺序。
	// ────────────────────────────────────────────
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

	// ────────────────────────────────────────────
	// R09: 非工作时间写操作
	// 凌晨 00:00 ~ 06:00 期间出现写操作（非读操作）。
	// 正常用户很少在这个时段进行写操作，
	// 可能是自动化脚本或被盗用的凭证在作业，触发告警。
	// ────────────────────────────────────────────
	{ID: "R09_OFF_HOURS_WRITE", Description: "write ops during off-hours (0:00-6:00)",
		Condition: func(ctx *types.ConnectionContext, _ []*types.ConnectionSummary, _ types.RiskLevel, _ *portrait.Store) bool {
			for _, e := range ctx.Events {
				if !READ_OPS[e.OpType] && isOffHours(e.Timestamp) {
					return true
				}
			}
			return false
		}, Action: types.ALERT},

	// ────────────────────────────────────────────
	// R10: 写操作比例过高
	// 当前连接中写操作占比超过 80%。
	// 正常用户的连接通常以读操作（浏览、下载）为主，
	// 极高的写比例可能意味着数据篡改或自动化攻击，触发告警。
	// ────────────────────────────────────────────
	{ID: "R10_HIGH_WRITE_RATIO", Description: "write ratio > 80% in current connection",
		Condition: func(ctx *types.ConnectionContext, _ []*types.ConnectionSummary, _ types.RiskLevel, _ *portrait.Store) bool {
			return ctx.WriteRatio() > 0.8
		}, Action: types.ALERT},

	// ────────────────────────────────────────────
	// R99: 风险等级兜底
	// 所有前置规则均未命中时，根据静态风险等级决定动作。
	// 条件恒为 true，作为最后的安全网。
	// Engine 遇到此规则时会将 riskLevel 传入 staticRiskDecision：
	//   L1 → AUDIT（仅审计记录）
	//   L2 → ALERT（触发告警）
	//   其他 → ALLOW（放行）
	// ────────────────────────────────────────────
	{ID: "R99_STATIC_RISK", Description: "fallback: static risk level",
		Condition: func(_ *types.ConnectionContext, _ []*types.ConnectionSummary, _ types.RiskLevel, _ *portrait.Store) bool {
			return true
		}, Action: types.ALLOW},
}
