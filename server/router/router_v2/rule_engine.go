package router_v2

import (
	"log"
	"sort"
	"strings"

	"Threshold/pkg/types"
)

// CompiledRule 编译后的规则（支持快速匹配）
type CompiledRule struct {
	Rule
	MethodPattern string // 匹配模式："GET", "POST", "TCP", "*"
	PathPrefix    string // 路径前缀（通配符 * 之前的部分）
	IsWildcard    bool   // 是否通配符匹配
	RiskLevel     RiskLevel
}

// RuleEngine 规则引擎
type RuleEngine struct {
	rules []CompiledRule
}

// NewRuleEngine 从配置创建规则引擎
func NewRuleEngine(cfg *Config) *RuleEngine {
	compiled := make([]CompiledRule, 0, len(cfg.Rules))
	for _, r := range cfg.Rules {
		cr := CompiledRule{
			Rule:      r,
			RiskLevel: StringToRiskLevel(r.RiskLevel),
		}
		// 预处理匹配模式
		cr.MethodPattern = r.Match.Method
		// 处理路径通配符
		if strings.HasSuffix(r.Match.Path, "*") {
			cr.IsWildcard = true
			cr.PathPrefix = strings.TrimSuffix(r.Match.Path, "*")
		} else {
			cr.IsWildcard = false
			cr.PathPrefix = r.Match.Path
		}
		compiled = append(compiled, cr)
	}

	// 按 priority 从高到低排序
	sort.Slice(compiled, func(i, j int) bool {
		return compiled[i].Priority > compiled[j].Priority
	})

	log.Printf("[RouterV2] loaded %d rules", len(compiled))
	return &RuleEngine{rules: compiled}
}

// Match 匹配请求，返回 RiskLevel，未匹配则返回默认 L1
func (e *RuleEngine) Match(parsed *types.ParsedRequest) RiskLevel {
	method := parsed.Method
	path := parsed.Path

	for _, rule := range e.rules {
		// 1. 方法匹配
		if rule.MethodPattern != "*" && rule.MethodPattern != method {
			continue
		}

		// 2. 路径匹配
		if rule.IsWildcard {
			// 通配符匹配：检查前缀
			if !strings.HasPrefix(path, rule.PathPrefix) {
				continue
			}
		} else {
			// 精确匹配
			if path != rule.PathPrefix {
				continue
			}
		}

		// 命中
		log.Printf("[RouterV2] rule %s matched: %s %s -> %v",
			rule.ID, method, path, rule.RiskLevel)
		return rule.RiskLevel
	}

	// 未匹配，默认 L1
	log.Printf("[RouterV2] no rule matched: %s %s -> default L1", method, path)
	return L1
}
