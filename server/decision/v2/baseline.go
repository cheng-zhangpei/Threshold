package v2

import (
	"math"
	"sync"
	"time"

	"Threshold/pkg/types"
)

// BaselineStore 设备/用户行为基线
// 用于时序异常检测：比较当前行为与历史基线的偏离程度
//
// 核心思路：
//   - 每个设备维护 hourlyDistribution[24]（每小时操作占比）
//   - 每个设备维护事件率的移动平均和标准差
//   - 新数据以指数衰减方式融入基线（alpha=0.1）
//   - 异常检测：当前值偏离均值超过 N 个标准差 → 异常
type BaselineStore struct {
	mu        sync.RWMutex
	baselines map[string]*DeviceBaseline // deviceUUID → baseline
}

type DeviceBaseline struct {
	DeviceUUID       string
	TotalConnections int
	HourlyDist       [24]float64 // 每小时连接占比（归一化后和为1）
	EventRateMean    float64     // 每连接平均事件数（指数移动平均）
	EventRateVar     float64     // 事件率方差
	WriteRatioMean   float64     // 写操作占比均值
	WriteRatioVar    float64     // 写操作占比方差
	LastUpdate       time.Time
	ViolationCount   int // 历史违规次数
}

func NewBaselineStore() *BaselineStore {
	return &BaselineStore{
		baselines: make(map[string]*DeviceBaseline),
	}
}

const (
	ewmaAlpha      = 0.1 // 指数加权移动平均系数
	sigmaThreshold = 2.0 // 超过 2 个标准差视为异常
)

// Update 用新的连接摘要更新基线
func (bs *BaselineStore) Update(summary *types.ConnectionSummary) {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	bl := bs.getOrCreate(summary.DeviceUUID)
	bl.TotalConnections++

	// 更新小时分布
	hour := summary.ConnectedAt.Hour()
	// 先衰减旧数据
	for i := range bl.HourlyDist {
		bl.HourlyDist[i] *= (1 - ewmaAlpha)
	}
	bl.HourlyDist[hour] += ewmaAlpha
	// 归一化
	norm := 0.0
	for _, v := range bl.HourlyDist {
		norm += v
	}
	if norm > 0 {
		for i := range bl.HourlyDist {
			bl.HourlyDist[i] /= norm
		}
	}

	// 更新事件率（Welford 在线算法）
	newRate := float64(summary.TotalEvents)
	bl.updateMeanVar(&bl.EventRateMean, &bl.EventRateVar, newRate)

	// 更新写比例
	bl.updateMeanVar(&bl.WriteRatioMean, &bl.WriteRatioVar, summary.WriteRatio)

	bl.LastUpdate = time.Now()
}

// RecordViolation 记录一次违规
func (bs *BaselineStore) RecordViolation(deviceUUID string) {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	bl := bs.getOrCreate(deviceUUID)
	bl.ViolationCount++
}

// DetectAnomalies 检测当前连接相对于基线的异常
func (bs *BaselineStore) DetectAnomalies(deviceUUID string, currentHour int, eventRate float64, writeRatio float64) (anomalies []string, score float64) {
	bs.mu.RLock()
	defer bs.mu.RUnlock()

	bl, ok := bs.baselines[deviceUUID]
	if !ok || bl.TotalConnections < 3 {
		return nil, 0 // 数据不足，不检测
	}

	totalScore := 0.0

	// 1. 时间分布异常：当前小时的连接占比远低于基线
	if bl.HourlyDist[currentHour] < 0.02 && bl.TotalConnections >= 10 {
		anomalies = append(anomalies, "off_hours_pattern")
		totalScore += 0.3
	}

	// 2. 事件率异常：偏离均值超过 N 个标准差
	if bl.EventRateVar > 0 {
		sigma := math.Sqrt(bl.EventRateVar)
		zScore := math.Abs(eventRate-bl.EventRateMean) / sigma
		if zScore > sigmaThreshold {
			anomalies = append(anomalies, "event_rate_spike")
			totalScore += math.Min(zScore/sigmaThreshold*0.3, 0.5)
		}
	}

	// 3. 写比例异常
	if bl.WriteRatioVar > 0 {
		sigma := math.Sqrt(bl.WriteRatioVar)
		zScore := math.Abs(writeRatio-bl.WriteRatioMean) / sigma
		if zScore > sigmaThreshold {
			anomalies = append(anomalies, "write_ratio_drift")
			totalScore += math.Min(zScore/sigmaThreshold*0.2, 0.4)
		}
	}

	return anomalies, math.Min(totalScore, 1.0)
}

func (bl *DeviceBaseline) updateMeanVar(mean, variance *float64, newValue float64) {
	// Welford 在线算法
	n := float64(bl.TotalConnections)
	if n <= 1 {
		*mean = newValue
		*variance = 0
		return
	}
	delta := newValue - *mean
	*mean += delta / n
	delta2 := newValue - *mean
	*variance = (*variance*(n-2) + delta*delta2) / (n - 1)
}

func (bs *BaselineStore) getOrCreate(deviceUUID string) *DeviceBaseline {
	bl, ok := bs.baselines[deviceUUID]
	if !ok {
		bl = &DeviceBaseline{DeviceUUID: deviceUUID}
		bs.baselines[deviceUUID] = bl
	}
	return bl
}

// GetBaseline 获取基线快照（供外部查询）
func (bs *BaselineStore) GetBaseline(deviceUUID string) *DeviceBaseline {
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	bl, ok := bs.baselines[deviceUUID]
	if !ok {
		return nil
	}
	// 返回副本
	copy := *bl
	return &copy
}
