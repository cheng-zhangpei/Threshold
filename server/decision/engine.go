package decision

import (
	"Threshold/pkg/types"
	"Threshold/server/portrait"
)

type Engine struct {
	rules []Rule
	store *portrait.Store
}

func NewEngine(store *portrait.Store) *Engine {
	return &Engine{rules: DECISION_RULES, store: store}
}

func (e *Engine) Evaluate(ctx *types.ConnectionContext, history []*types.ConnectionSummary, riskLevel types.RiskLevel) *types.Decision {
	for _, rule := range e.rules {
		if rule.Condition(ctx, history, riskLevel, e.store) {
			if rule.ID == "R99_STATIC_RISK" {
				return staticRiskDecision(riskLevel)
			}
			return &types.Decision{Action: rule.Action, Reason: rule.Description, RuleID: rule.ID}
		}
	}
	return &types.Decision{Action: types.ALLOW, Reason: "no_rule_matched", RuleID: "none"}
}

func staticRiskDecision(level types.RiskLevel) *types.Decision {
	switch level {
	case types.L1:
		return &types.Decision{Action: types.AUDIT, Reason: "L1 write operation", RuleID: "R99"}
	case types.L2:
		return &types.Decision{Action: types.ALERT, Reason: "L2 high risk operation", RuleID: "R99"}
	default:
		return &types.Decision{Action: types.ALLOW, Reason: "default allow", RuleID: "R99"}
	}
}
