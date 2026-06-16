package router_v2

import "Threshold/pkg/types"

// RiskLevel 复用 types.RiskLevel
type RiskLevel = types.RiskLevel

const (
	L0 = types.L0
	L1 = types.L1
	L2 = types.L2
	L3 = types.L3
)

// StringToRiskLevel 字符串转 RiskLevel
func StringToRiskLevel(s string) RiskLevel {
	switch s {
	case "L0":
		return L0
	case "L1":
		return L1
	case "L2":
		return L2
	case "L3":
		return L3
	default:
		return L1
	}
}
