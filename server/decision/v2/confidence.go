package v2

import "math"

// ConfidenceCalculator 计算决策置信度
//
// 置信度反映的是「我们对风险评估结果有多大把握」
// 数据量越少，置信度越低，决策越保守（倾向 AUDIT 而非 BLOCK）
//
// 三个维度：
//  1. 连接次数：设备历史连接越多，画像越可靠
//  2. 基线建立状态：时序基线需要足够的数据点
//  3. 语义覆盖度：有多少风险因子有足够的数据来评估
type ConfidenceCalculator struct {
	minDataPoints    int
	fullConfidenceAt int
}

func NewConfidenceCalculator(minDataPoints, fullConfidenceAt int) *ConfidenceCalculator {
	return &ConfidenceCalculator{
		minDataPoints:    minDataPoints,
		fullConfidenceAt: fullConfidenceAt,
	}
}

// Compute 计算置信度
// dataPoints: 历史连接数
// factorCoverage: 有足够数据评估的因子比例 (0.0-1.0)
func (cc *ConfidenceCalculator) Compute(dataPoints int, factorCoverage float64) float64 {
	if dataPoints == 0 {
		return 0.1 // 极低置信度
	}

	// 数据量置信度：sigmoid 曲线，在 minDataPoints 开始上升，fullConfidenceAt 趋近 1.0
	dataConfidence := sigmoid(float64(dataPoints), float64(cc.minDataPoints), float64(cc.fullConfidenceAt))

	// 综合置信度 = 数据量置信度 * 因子覆盖度
	// factorCoverage 兜底为 0.5（至少有一半因子能评估）
	if factorCoverage < 0.5 {
		factorCoverage = 0.5
	}

	confidence := dataConfidence * factorCoverage

	// 下限 0.1，上限 1.0
	return math.Max(0.1, math.Min(1.0, confidence))
}

// sigmoid: 平滑的 S 曲线
// x=low 时输出 ≈ 0.05
// x=high 时输出 ≈ 0.95
func sigmoid(x, low, high float64) float64 {
	mid := (low + high) / 2
	steepness := 4.0 / (high - low) // 控制曲线陡峭程度
	return 1.0 / (1.0 + math.Exp(-steepness*(x-mid)))
}
