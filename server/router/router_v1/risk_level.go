package router_v1

import "Threshold/pkg/types"

// IsReadOp 判断 HTTP 方法是否为只读操作
func IsReadOp(method string) bool {
	return method == "GET" || method == "HEAD" || method == "OPTIONS"
}

// ClassifyByMethod 根据 HTTP 方法进行基础风险分级
// GET/HEAD/OPTIONS -> L0 (只读查询，直接穿透)
// POST/PUT/PATCH -> L1 (写操作，需审计)
// DELETE -> L2 (高风险，需告警)
func ClassifyByMethod(method string) types.RiskLevel {
	switch method {
	case "GET", "HEAD", "OPTIONS":
		return types.L0
	case "DELETE":
		return types.L2
	default:
		return types.L1
	}
}
