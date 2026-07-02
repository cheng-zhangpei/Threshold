package v2

import "Threshold/pkg/types"

// RiskFactor 单个风险因子的评估结果
type RiskFactor struct {
	Name      string  `json:"name"`      // 因子名称
	Score     float64 `json:"score"`     // 原始分 0.0-1.0
	Weight    float64 `json:"weight"`    // 权重
	Weighted  float64 `json:"weighted"`  // Score * Weight
	Triggered bool    `json:"triggered"` // 是否触发
	Detail    string  `json:"detail"`    // 可读描述
}

// RiskAssessment 完整风险评估结果
type RiskAssessment struct {
	RiskScore  float64      `json:"risk_score"`  // 加权风险分 0.0-1.0
	Confidence float64      `json:"confidence"`  // 置信度 0.0-1.0
	Effective  float64      `json:"effective"`   // RiskScore * Confidence
	Factors    []RiskFactor `json:"factors"`     // 各因子明细
	Anomalies  []string     `json:"anomalies"`   // 时序异常标记
	DataPoints int          `json:"data_points"` // 历史数据量
}

// DecisionConfig 决策阈值配置
type DecisionConfig struct {
	// 三层阈值
	AuditThreshold float64 `yaml:"audit_threshold"` // 超过此值 → AUDIT
	AlertThreshold float64 `yaml:"alert_threshold"` // 超过此值 → ALERT
	BlockThreshold float64 `yaml:"block_threshold"` // 超过此值 → BLOCK

	// 代价模型
	FalsePositiveCost float64 `yaml:"false_positive_cost"` // 误拦截代价
	FalseNegativeCost float64 `yaml:"false_negative_cost"` // 漏放代价

	// 置信度参数
	MinDataPoints    int `yaml:"min_data_points"`    // 低于此数据量，置信度打折
	FullConfidenceAt int `yaml:"full_confidence_at"` // 达到此数据量，置信度=1.0
}

func DefaultDecisionConfig() DecisionConfig {
	return DecisionConfig{
		AuditThreshold:    0.3,
		AlertThreshold:    0.6,
		BlockThreshold:    0.8,
		FalsePositiveCost: 1.0,
		FalseNegativeCost: 10.0,
		MinDataPoints:     3,
		FullConfidenceAt:  50,
	}
}

// FactorConfig 因子权重配置
type FactorConfig struct {
	Name   string  `yaml:"name"`
	Weight float64 `yaml:"weight"`
	Enable bool    `yaml:"enable"`
}

// EngineConfig 整体引擎配置
type EngineConfig struct {
	Decision DecisionConfig `yaml:"decision"`
	Factors  []FactorConfig `yaml:"factors"`
}

func DefaultEngineConfig() EngineConfig {
	return EngineConfig{
		Decision: DefaultDecisionConfig(),
		Factors: []FactorConfig{
			{Name: "off_hours", Weight: 0.15, Enable: true},
			{Name: "write_ratio", Weight: 0.15, Enable: true},
			{Name: "bulk_delete", Weight: 0.20, Enable: true},
			{Name: "brute_force", Weight: 0.25, Enable: true},
			{Name: "frequency_anomaly", Weight: 0.10, Enable: true},
			{Name: "device_trust", Weight: 0.10, Enable: true},
			{Name: "history_violations", Weight: 0.05, Enable: true},
		},
	}
}

// ExtendedDecision 扩展决策结果，包含完整评估上下文
type ExtendedDecision struct {
	*types.Decision
	Assessment *RiskAssessment `json:"assessment,omitempty"`
}
