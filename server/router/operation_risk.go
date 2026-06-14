package router

import (
	"regexp"
	"strings"

	"Threshold/pkg/types"
)

// OPERATION_RISK 静态操作风险映射表
// key: "METHOD /api/path" 格式的操作标识
// value: 对应的风险等级 (L0/L1/L2/L3)
// 未知操作默认 L1，宁可误审不漏放
var OPERATION_RISK = map[string]types.RiskLevel{
	// L0 - 只读查询，直接穿透到 OutputBuffer
	"GET /api/cloud/public/images":           types.L0,
	"GET /api/cloud/public/images/download":  types.L0,
	"GET /api/cloud/private/images":          types.L0,
	"GET /api/cloud/private/images/download": types.L0,
	"GET /api/local/images":                  types.L0,
	"GET /api/local/images/download":         types.L0,
	"GET /api/local/stats":                   types.L0,
	"GET /api/vms/status":                    types.L0,
	"GET /api/vms/running":                   types.L0,
	"GET /api/vms/log":                       types.L0,
	"GET /api/security/policy":               types.L0,
	"GET /api/audit/events":                  types.L0,

	// L1 - 写操作，需审计（入队 Worker 处理）
	"POST /api/cloud/public/images":           types.L1,
	"POST /api/cloud/private/images":          types.L1,
	"POST /api/local/images":                  types.L1,
	"POST /api/vms/start":                     types.L1,
	"POST /api/vms/stop":                      types.L1,
	"PUT /api/vms/config":                     types.L1,
	"PATCH /api/vms/config":                   types.L1,

	// L2 - 高风险操作，需告警
	"DELETE /api/cloud/public/images":          types.L2,
	"DELETE /api/cloud/private/images":         types.L2,
	"DELETE /api/local/images":                 types.L2,
}

// WILDCARD_RISK_RULES 通配符模式的操作风险规则
// 用于匹配未在精确映射表中列出的操作
// Pattern 格式: "METHOD /path/pattern"，其中 * 匹配任意路径段
var WILDCARD_RISK_RULES = []struct {
	Pattern string
	Level  types.RiskLevel
}{
	{"POST /api/vms/*", types.L1},
	{"DELETE /*", types.L2},
}

// compiledRule 预编译的通配符规则
type compiledRule struct {
	regex *regexp.Regexp
	level types.RiskLevel
}

var compiledWildcardRules []compiledRule

func init() {
	for _, r := range WILDCARD_RISK_RULES {
		regexStr := "^" + convertWildcardToRegex(r.Pattern) + "$"
		compiledWildcardRules = append(compiledWildcardRules, compiledRule{
			regex: regexp.MustCompile(regexStr),
			level: r.Level,
		})
	}
}

// convertWildcardToRegex 将 "METHOD /path/*/suffix" 格式的通配符模式
// 转换为正则表达式字符串
// - 路径中的 * 转换为 [^/]+（匹配单个路径段，不含斜杠）
// - 路径末尾的 * 转换为 .*（匹配任意剩余路径）
func convertWildcardToRegex(pattern string) string {
	parts := strings.SplitN(pattern, " ", 2)
	if len(parts) != 2 {
		return regexp.QuoteMeta(pattern)
	}
	method := regexp.QuoteMeta(parts[0])
	path := parts[1]

	var result strings.Builder
	for i := 0; i < len(path); i++ {
		if path[i] == '*' {
			// 判断 * 后面是否还有字符
			if i == len(path)-1 {
				// 路径末尾的 *，匹配任意内容（含斜杠）
				result.WriteString(".*")
			} else {
				// 路径中间的 *，只匹配单个路径段
				result.WriteString("[^/]+")
			}
		} else {
			result.WriteString(regexp.QuoteMeta(string(path[i])))
		}
	}
	return method + " " + result.String()
}

// OperationRiskTable 操作风险映射表（含精确匹配 + 通配符匹配）
type OperationRiskTable struct {
	directRules  map[string]types.RiskLevel
	wildcards    []compiledRule
	defaultLevel types.RiskLevel
}

// NewOperationRiskTable 创建操作风险映射表
// 使用全局 OPERATION_RISK 精确映射表和 WILDCARD_RISK_RULES 通配符规则
func NewOperationRiskTable() *OperationRiskTable {
	return &OperationRiskTable{
		directRules:  OPERATION_RISK,
		wildcards:    compiledWildcardRules,
		defaultLevel: types.L1,
	}
}

// Lookup 根据 HTTP 方法和路径查找操作的风险等级
// 查找顺序: 精确匹配 -> 通配符匹配 -> 默认 L1
func (t *OperationRiskTable) Lookup(method string, path string) types.RiskLevel {
	key := method + " " + path

	// 精确匹配
	if level, ok := t.directRules[key]; ok {
		return level
	}

	// 通配符匹配
	for _, rule := range t.wildcards {
		if rule.regex.MatchString(key) {
			return rule.level
		}
	}

	// 默认 L1：未知操作宁可误审不漏放
	return t.defaultLevel
}
