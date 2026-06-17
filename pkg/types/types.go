package types

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
	"time"
)

type RiskLevel int

const (
	L0 RiskLevel = iota
	L1
	L2
	L3
)

type Action int

const (
	ALLOW Action = iota
	AUDIT
	ALERT
	THROTTLE
	BLOCK
	BLOCK_DEVICE
	BLOCK_LOGIN
	BLOCK_WRITE_OPS
	REQUIRE_2FA
	QUARANTINE_AND_ALERT
	BLACKLIST_DEVICE
)

var actionNames = [...]string{
	ALLOW:                "ALLOW",
	AUDIT:                "AUDIT",
	ALERT:                "ALERT",
	THROTTLE:             "THROTTLE",
	BLOCK:                "BLOCK",
	BLOCK_DEVICE:         "BLOCK_DEVICE",
	BLOCK_LOGIN:          "BLOCK_LOGIN",
	BLOCK_WRITE_OPS:      "BLOCK_WRITE_OPS",
	REQUIRE_2FA:          "REQUIRE_2FA",
	QUARANTINE_AND_ALERT: "QUARANTINE_AND_ALERT",
	BLACKLIST_DEVICE:     "BLACKLIST_DEVICE",
}

func (a Action) String() string {
	if int(a) < len(actionNames) {
		return actionNames[a]
	}
	return fmt.Sprintf("Action(%d)", int(a))
}

type Decision struct {
	Action Action
	Reason string
	RuleID string
}

type DeviceFingerprint struct {
	UUID     *string
	OS       *string
	IP       *string
	Port     *string
	Protocol *string
	Reserved *string
}

type EventRecord struct {
	OpType    string
	Timestamp time.Time
}

type ConnectionContext struct {
	ConnectionID   string
	UserID         string
	DeviceUUID     string
	ConnectedAt    time.Time
	IP             string
	Events         []EventRecord
	TriggeredFlags []string
	Protocol       string
	TargetAddr     string
}

func (c *ConnectionContext) RecordEvent(opType string) {
	c.Events = append(c.Events, EventRecord{OpType: opType, Timestamp: time.Now()})
}

func (c *ConnectionContext) EventCounts() map[string]int {
	counts := make(map[string]int)
	for _, e := range c.Events {
		counts[e.OpType]++
	}
	return counts
}

func isReadOp(opType string) bool {
	return strings.HasPrefix(strings.TrimSpace(opType), "GET ")
}

func (c *ConnectionContext) WriteRatio() float64 {
	if len(c.Events) == 0 {
		return 0.0
	}
	writeCount := 0
	for _, e := range c.Events {
		if !isReadOp(e.OpType) {
			writeCount++
		}
	}
	return float64(writeCount) / float64(len(c.Events))
}

type ConnectionSummary struct {
	ConnectionID   string
	UserID         string
	DeviceUUID     string
	ConnectedAt    time.Time
	EndedAt        time.Time
	DurationSec    float64
	IP             string
	EventCounts    map[string]int
	FlagsTriggered []string
	OffHoursWrites int
	TotalEvents    int
	WriteRatio     float64
}

type PoolPolicy struct {
	MinWorkers             int
	MaxWorkers             int
	ScaleUpThreshold       int
	ScaleUpStep            int
	MaxQueueSize           int
	IdleTimeoutSec         int
	HealthCheckIntervalSec int
}

type ParsedRequest struct {
	ConnectionID string
	DeviceUUID   string
	UserID       string
	Timestamp    time.Time
	Method       string
	Path         string
	Headers      map[string]string
	Body         []byte
	Fingerprint  DeviceFingerprint
	OpKey        string
	TargetAddr   string `json:"target_addr,omitempty"` // 目标服务器地址，如 "example.com:80"
	// todo 最好TCP要拓展更多的语义，可以作为可选字段，由于增强决策引擎的功能，需要和决策引擎一起设计我认为会比较合理
}

func ParseProxyRequest(connectionID, deviceUUID, userID string, timestamp int64, rawHTTPRequest []byte) (*ParsedRequest, error) {
	req := &ParsedRequest{
		ConnectionID: connectionID, DeviceUUID: deviceUUID, UserID: userID,
		Timestamp: time.UnixMilli(timestamp), Headers: make(map[string]string),
	}
	if len(rawHTTPRequest) == 0 {
		return nil, fmt.Errorf("empty raw_http_request")
	}
	if err := req.parseHTTPRequest(rawHTTPRequest); err != nil {
		return nil, err
	}
	//req.extractFingerprint()
	req.OpKey = req.Method + " " + req.Path
	return req, nil
}
func (r *ParsedRequest) parseHTTPRequest(raw []byte) error {
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	if !scanner.Scan() {
		return fmt.Errorf("missing request line")
	}
	parts := strings.SplitN(strings.TrimSpace(scanner.Text()), " ", 3)
	if len(parts) < 2 {
		return fmt.Errorf("invalid request line")
	}
	r.Method = strings.ToUpper(parts[0])
	r.Path = parts[1]
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			break
		}
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		r.Headers[strings.TrimSpace(line[:idx])] = strings.TrimSpace(line[idx+1:])
	}
	var body bytes.Buffer
	for scanner.Scan() {
		body.Write(scanner.Bytes())
		body.WriteByte(10)
	}
	r.Body = bytes.TrimRight(body.Bytes(), "\n")

	// 提取 Host 头作为目标地址
	if host, ok := r.Headers["Host"]; ok && host != "" {
		r.TargetAddr = host
		// 注意：如果 Host 不带端口，可根据请求的 Scheme 补充默认端口
		// 例如：如果 r.Method 不是 CONNECT，且没有端口，对于 http 默认 80，https 默认 443
		// 目前仅作提取，不加默认端口，保证后续可用
	}
	return scanner.Err()
}
func (r *ParsedRequest) extractFingerprint() {
	set := func(val string) *string {
		if val == "" {
			return nil
		}
		return &val
	}
	r.Fingerprint = DeviceFingerprint{
		UUID: set(r.Headers["X-Proxy-UUID"]), OS: set(r.Headers["X-Proxy-OS"]),
		IP: set(r.Headers["X-Proxy-IP"]), Port: set(r.Headers["X-Proxy-Port"]),
		Protocol: set(r.Headers["X-Proxy-Protocol"]), Reserved: set(r.Headers["X-Proxy-Reserved"]),
	}
}

type Task struct {
	Req       *ParsedRequest
	RiskLevel RiskLevel
	ResultCh  chan *Decision
}
