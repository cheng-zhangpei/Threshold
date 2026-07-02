package v2

import (
	"fmt"
	"strings"
	"time"

	"Threshold/pkg/types"
	"Threshold/server/portrait"
)

// EvaluateInput 评估输入（聚合所有层的数据）
type EvaluateInput struct {
	Ctx       *types.ConnectionContext
	History   []*types.ConnectionSummary
	RiskLevel types.RiskLevel
	Profile   *portrait.UserProfile
	Baseline  *BaselineStore
}

// FactorFunc 风险因子评估函数
type FactorFunc func(input *EvaluateInput) RiskFactor

// ============================================================
// 因子 1: 非工作时间操作 (0:00-6:00)
// ============================================================
func OffHoursFactor(input *EvaluateInput) RiskFactor {
	f := RiskFactor{Name: "off_hours", Weight: 0.15}
	now := time.Now()
	if now.Hour() >= 0 && now.Hour() < 6 {
		f.Score = 0.7
		f.Triggered = true
		f.Detail = fmt.Sprintf("connection at %02d:00 (off-hours)", now.Hour())
	} else {
		f.Score = 0.0
		f.Detail = fmt.Sprintf("connection at %02d:00 (business hours)", now.Hour())
	}
	f.Weighted = f.Score * f.Weight
	return f
}

// ============================================================
// 因子 2: 写操作比例过高
// ============================================================
func WriteRatioFactor(input *EvaluateInput) RiskFactor {
	f := RiskFactor{Name: "write_ratio", Weight: 0.15}
	ratio := input.Ctx.WriteRatio()
	if len(input.Ctx.Events) == 0 {
		f.Detail = "no events yet"
		return f
	}

	// 与历史基线对比
	baseline := input.Baseline.GetBaseline(input.Ctx.DeviceUUID)
	if baseline != nil && baseline.TotalConnections >= 5 {
		delta := ratio - baseline.WriteRatioMean
		if delta > 0.3 {
			f.Score = 0.8
			f.Triggered = true
			f.Detail = fmt.Sprintf("write_ratio=%.1f%% vs baseline %.1f%% (drift +%.1f%%)",
				ratio*100, baseline.WriteRatioMean*100, delta*100)
		} else {
			f.Score = ratio * 0.3 // 绝对值也给一点分
			f.Detail = fmt.Sprintf("write_ratio=%.1f%% (within baseline)", ratio*100)
		}
	} else {
		// 无基线，用绝对阈值
		if ratio > 0.8 {
			f.Score = 0.6
			f.Triggered = true
			f.Detail = fmt.Sprintf("write_ratio=%.1f%% (>80%%, no baseline)", ratio*100)
		} else {
			f.Score = 0.0
			f.Detail = fmt.Sprintf("write_ratio=%.1f%%", ratio*100)
		}
	}
	f.Weighted = f.Score * f.Weight
	return f
}

// ============================================================
// 因子 3: 批量删除
// ============================================================
func BulkDeleteFactor(input *EvaluateInput) RiskFactor {
	f := RiskFactor{Name: "bulk_delete", Weight: 0.20}
	deleteCount := 0
	for _, e := range input.Ctx.Events {
		if strings.Contains(e.OpType, "delete") || strings.Contains(e.OpType, "DELETE") {
			deleteCount++
		}
	}

	if deleteCount >= 3 {
		f.Score = 0.9
		f.Triggered = true
		f.Detail = fmt.Sprintf("%d delete operations in current connection", deleteCount)
	} else if deleteCount >= 1 {
		f.Score = 0.3
		f.Detail = fmt.Sprintf("%d delete operations", deleteCount)
	} else {
		f.Detail = "no delete operations"
	}
	f.Weighted = f.Score * f.Weight
	return f
}

// ============================================================
// 因子 4: 暴力尝试（连续登录失败）
// ============================================================
func BruteForceFactor(input *EvaluateInput) RiskFactor {
	f := RiskFactor{Name: "brute_force", Weight: 0.25}
	failCount := 0
	for _, e := range input.Ctx.Events {
		if strings.Contains(e.OpType, "login_failed") {
			failCount++
		}
	}

	if failCount >= 5 {
		f.Score = 1.0
		f.Triggered = true
		f.Detail = fmt.Sprintf("%d login failures (brute force)", failCount)
	} else if failCount >= 3 {
		f.Score = 0.5
		f.Triggered = true
		f.Detail = fmt.Sprintf("%d login failures (suspicious)", failCount)
	} else {
		f.Detail = fmt.Sprintf("%d login failures", failCount)
	}
	f.Weighted = f.Score * f.Weight
	return f
}

// ============================================================
// 因子 5: 频率异常（时序检测）
// ============================================================
func FrequencyAnomalyFactor(input *EvaluateInput) RiskFactor {
	f := RiskFactor{Name: "frequency_anomaly", Weight: 0.10}

	anomalies, score := input.Baseline.DetectAnomalies(
		input.Ctx.DeviceUUID,
		time.Now().Hour(),
		float64(len(input.Ctx.Events)),
		input.Ctx.WriteRatio(),
	)

	if len(anomalies) > 0 {
		f.Score = score
		f.Triggered = true
		f.Detail = fmt.Sprintf("anomalies: %s", strings.Join(anomalies, ", "))
	} else {
		f.Detail = "no temporal anomalies"
	}
	f.Weighted = f.Score * f.Weight
	return f
}

// ============================================================
// 因子 6: 设备信任度
// ============================================================
func DeviceTrustFactor(input *EvaluateInput) RiskFactor {
	f := RiskFactor{Name: "device_trust", Weight: 0.10}
	profile := input.Profile

	if profile == nil || profile.TotalConnections == 0 {
		f.Score = 0.5 // 新设备，中等风险
		f.Detail = "new device, no history"
		f.Weighted = f.Score * f.Weight
		return f
	}

	// 设备是否已知
	known := false
	for _, d := range profile.KnownDevices {
		if d == input.Ctx.DeviceUUID {
			known = true
			break
		}
	}
	if !known && profile.TotalConnections > 5 {
		f.Score = 0.7
		f.Triggered = true
		f.Detail = fmt.Sprintf("unknown device for established user (total_conn=%d)",
			profile.TotalConnections)
	} else if profile.TotalConnections < 5 {
		f.Score = 0.3
		f.Detail = fmt.Sprintf("low history (conn=%d)", profile.TotalConnections)
	} else {
		f.Detail = fmt.Sprintf("known device (conn=%d)", profile.TotalConnections)
	}
	f.Weighted = f.Score * f.Weight
	return f
}

// ============================================================
// 因子 7: 历史违规记录
// ============================================================
func HistoryViolationFactor(input *EvaluateInput) RiskFactor {
	f := RiskFactor{Name: "history_violations", Weight: 0.05}
	profile := input.Profile

	if profile == nil {
		f.Detail = "no profile"
		return f
	}

	if profile.TotalConnections > 0 {
		violationRate := float64(profile.AlertCount) / float64(profile.TotalConnections)
		if violationRate > 0.5 {
			f.Score = 0.9
			f.Triggered = true
			f.Detail = fmt.Sprintf("high violation rate: %.0f%% (%d/%d)",
				violationRate*100, profile.AlertCount, profile.TotalConnections)
		} else if violationRate > 0.2 {
			f.Score = 0.5
			f.Detail = fmt.Sprintf("moderate violations: %.0f%%", violationRate*100)
		} else {
			f.Detail = fmt.Sprintf("low violations: %.0f%%", violationRate*100)
		}
	}
	f.Weighted = f.Score * f.Weight
	return f
}

// AllFactors 返回所有默认因子
func AllFactors() []FactorFunc {
	return []FactorFunc{
		OffHoursFactor,
		WriteRatioFactor,
		BulkDeleteFactor,
		BruteForceFactor,
		FrequencyAnomalyFactor,
		DeviceTrustFactor,
		HistoryViolationFactor,
	}
}
