package v2

import (
	"fmt"
	"log"
	"math"

	"Threshold/pkg/types"
	"Threshold/server/portrait"
)

// Engine 三层决策引擎
//
// 架构：
//
//	Layer 1: Filter — 硬规则过滤（黑名单、暴力破解等确定性决策）
//	Layer 2: Score  — 风险因子评估 + 时序异常检测 → 加权风险分
//	Layer 3: Decide — 置信度加权 + 代价敏感阈值 → 最终决策
//
// 设计原则：
//   - 无状态纯函数：输入上下文 → 输出决策，不持有跨请求状态
//   - BaselineStore 是唯一的有状态组件（时序基线），但不参与决策逻辑
//   - 可配置：因子权重、阈值、代价模型均可通过 YAML 配置
type Engine struct {
	cfg        EngineConfig
	factors    []FactorFunc
	baseline   *BaselineStore
	confidence *ConfidenceCalculator
	portrait   *portrait.Store
}

func NewEngine(cfg EngineConfig, portraitStore *portrait.Store) *Engine {
	return &Engine{
		cfg:        cfg,
		factors:    AllFactors(),
		baseline:   NewBaselineStore(),
		confidence: NewConfidenceCalculator(cfg.Decision.MinDataPoints, cfg.Decision.FullConfidenceAt),
		portrait:   portraitStore,
	}
}

func NewDefaultEngine(portraitStore *portrait.Store) *Engine {
	return NewEngine(DefaultEngineConfig(), portraitStore)
}

// Evaluate 三层决策入口
func (e *Engine) Evaluate(ctx *types.ConnectionContext, history []*types.ConnectionSummary, riskLevel types.RiskLevel) *types.Decision {
	var profile *portrait.UserProfile
	if e.portrait != nil {
		profile = e.portrait.GetProfile(ctx.UserID)
	}
	input := &EvaluateInput{
		Ctx: ctx, History: history, RiskLevel: riskLevel,
		Profile: profile, Baseline: e.baseline,
	}

	// Layer 1: 硬规则直接返回
	if hardDecision := e.filter(input); hardDecision != nil {
		return hardDecision
	}

	// Layer 2+3: 软评估 + 决策
	assessment := e.score(input)
	return e.decide(assessment, riskLevel)
}

// Assess 执行 Layer 1 + Layer 2，返回完整评估（不含最终决策）
func (e *Engine) Assess(ctx *types.ConnectionContext, history []*types.ConnectionSummary, riskLevel types.RiskLevel) *RiskAssessment {
	var profile *portrait.UserProfile
	if e.portrait != nil {
		profile = e.portrait.GetProfile(ctx.UserID)
	}

	input := &EvaluateInput{
		Ctx:       ctx,
		History:   history,
		RiskLevel: riskLevel,
		Profile:   profile,
		Baseline:  e.baseline,
	}

	// ====== Layer 1: Filter (硬规则) ======
	if hardDecision := e.filter(input); hardDecision != nil {
		return &RiskAssessment{
			RiskScore:  1.0,
			Confidence: 1.0,
			Effective:  1.0,
			Anomalies:  []string{"hard_rule:" + hardDecision.RuleID},
		}
	}

	// ====== Layer 2: Score (风险因子 + 时序) ======
	return e.score(input)
}

// filter Layer 1: 硬规则过滤
// 命中即返回决策，未命中返回 nil
func (e *Engine) filter(input *EvaluateInput) *types.Decision {
	// R1: 设备黑名单
	if e.portrait != nil && e.portrait.IsBlacklisted(input.Ctx.DeviceUUID) {
		log.Printf("[FILTER] device blacklisted: uuid=%s", input.Ctx.DeviceUUID)
		return &types.Decision{
			Action: types.BLACKLIST_DEVICE,
			Reason: "device is blacklisted",
			RuleID: "HARD_BLACKLIST",
		}
	}

	// R2: 连续暴力破解
	failCount := 0
	for _, ev := range input.Ctx.Events {
		if ev.OpType == "login_failed" {
			failCount++
		}
	}
	if failCount >= 5 {
		log.Printf("[FILTER] brute force: uuid=%s failures=%d", input.Ctx.DeviceUUID, failCount)
		return &types.Decision{
			Action: types.BLOCK_LOGIN,
			Reason: fmt.Sprintf("%d consecutive login failures", failCount),
			RuleID: "HARD_BRUTE_FORCE",
		}
	}

	// R3: 批量删除（>= 3）
	deleteCount := 0
	for _, ev := range input.Ctx.Events {
		if ev.OpType == "image.delete" || ev.OpType == "DELETE" {
			deleteCount++
		}
	}
	if deleteCount >= 3 {
		log.Printf("[FILTER] bulk delete: uuid=%s count=%d", input.Ctx.DeviceUUID, deleteCount)
		return &types.Decision{
			Action: types.BLOCK_DEVICE,
			Reason: fmt.Sprintf("%d delete operations", deleteCount),
			RuleID: "HARD_BULK_DELETE",
		}
	}

	// R4: 连续违规（最近 3 次连接全部有告警）
	if len(input.History) >= 3 {
		allFlagged := true
		for _, s := range input.History[len(input.History)-3:] {
			if len(s.FlagsTriggered) == 0 {
				allFlagged = false
				break
			}
		}
		if allFlagged {
			log.Printf("[FILTER] repeat offender: uuid=%s", input.Ctx.DeviceUUID)
			return &types.Decision{
				Action: types.BLACKLIST_DEVICE,
				Reason: "last 3 connections all triggered alerts",
				RuleID: "HARD_REPEAT_OFFENDER",
			}
		}
	}

	return nil
}

// score Layer 2: 风险因子评估 + 时序异常检测
func (e *Engine) score(input *EvaluateInput) *RiskAssessment {
	assessment := &RiskAssessment{
		DataPoints: len(input.History),
	}

	totalWeight := 0.0
	weightedSum := 0.0
	coveredFactors := 0

	for _, factorFn := range e.factors {
		f := factorFn(input)
		// 检查是否启用
		if !e.isFactorEnabled(f.Name) {
			continue
		}
		assessment.Factors = append(assessment.Factors, f)
		totalWeight += f.Weight
		weightedSum += f.Weighted
		if f.Score > 0 {
			coveredFactors++
		}
	}

	// 归一化风险分
	if totalWeight > 0 {
		assessment.RiskScore = math.Min(weightedSum/totalWeight, 1.0)
	}

	// 时序异常加分
	anomalies, anomalyScore := e.baseline.DetectAnomalies(
		input.Ctx.DeviceUUID,
		0, // hour will be filled by factor
		float64(len(input.Ctx.Events)),
		input.Ctx.WriteRatio(),
	)
	assessment.Anomalies = anomalies
	if anomalyScore > 0 {
		assessment.RiskScore = math.Min(assessment.RiskScore+anomalyScore*0.2, 1.0)
	}

	// 计算置信度
	factorCoverage := 1.0
	if len(e.factors) > 0 {
		factorCoverage = float64(coveredFactors) / float64(len(e.factors))
	}
	assessment.Confidence = e.confidence.Compute(assessment.DataPoints, factorCoverage)

	// 有效风险分 = 风险分 * 置信度
	assessment.Effective = assessment.RiskScore * assessment.Confidence

	return assessment
}

// decide Layer 3: 代价敏感决策
func (e *Engine) decide(assessment *RiskAssessment, riskLevel types.RiskLevel) *types.Decision {
	d := e.cfg.Decision

	// 静态风险等级调制
	effectiveScore := assessment.Effective
	switch riskLevel {
	case types.L3:
		effectiveScore = math.Min(effectiveScore*1.5, 1.0)
	case types.L2:
		effectiveScore = math.Min(effectiveScore*1.2, 1.0)
	}

	// 代价敏感比较
	// 当有效风险分 > 阈值时，比较「放行的期望代价」vs「拦截的期望代价」
	// 期望漏放代价 = effectiveScore * FalseNegativeCost
	// 期望误拦代价 = (1 - effectiveScore) * FalsePositiveCost
	negCost := effectiveScore * d.FalseNegativeCost
	posCost := (1 - effectiveScore) * d.FalsePositiveCost

	decision := &types.Decision{RuleID: "V2_ENGINE"}

	// 确定性硬规则已过，这里是软决策
	if effectiveScore >= d.BlockThreshold && negCost > posCost {
		decision.Action = types.BLOCK
		decision.Reason = fmt.Sprintf("risk=%.2f confidence=%.2f effective=%.2f (block threshold=%.2f)",
			assessment.RiskScore, assessment.Confidence, effectiveScore, d.BlockThreshold)
	} else if effectiveScore >= d.AlertThreshold {
		decision.Action = types.ALERT
		decision.Reason = fmt.Sprintf("risk=%.2f confidence=%.2f effective=%.2f (alert threshold=%.2f)",
			assessment.RiskScore, assessment.Confidence, effectiveScore, d.AlertThreshold)
	} else if effectiveScore >= d.AuditThreshold {
		decision.Action = types.AUDIT
		decision.Reason = fmt.Sprintf("risk=%.2f confidence=%.2f effective=%.2f (audit threshold=%.2f)",
			assessment.RiskScore, assessment.Confidence, effectiveScore, d.AuditThreshold)
	} else {
		decision.Action = types.ALLOW
		decision.Reason = fmt.Sprintf("risk=%.2f confidence=%.2f effective=%.2f (below all thresholds)",
			assessment.RiskScore, assessment.Confidence, effectiveScore)
	}

	log.Printf("[DECIDE] uuid=%s risk=%.3f conf=%.3f eff=%.3f action=%s reason=%s",
		"", assessment.RiskScore, assessment.Confidence, effectiveScore,
		decision.Action, decision.Reason)

	return decision
}

func (e *Engine) isFactorEnabled(name string) bool {
	for _, fc := range e.cfg.Factors {
		if fc.Name == name {
			return fc.Enable
		}
	}
	return true // 未配置的默认启用
}

// Baseline 基线存储（供外部更新）
func (e *Engine) Baseline() *BaselineStore {
	return e.baseline
}

// UpdateBaseline 用连接摘要更新基线
func (e *Engine) UpdateBaseline(summary *types.ConnectionSummary) {
	e.baseline.Update(summary)
}
