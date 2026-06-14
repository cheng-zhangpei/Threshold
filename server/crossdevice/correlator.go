package crossdevice

import (
	"sync"

	"Threshold/pkg/types"
)

// Correlator defines the interface for cross-device user correlation.
// Given a device UUID and user ID, it returns historically linked devices.
// Implementations can range from simple rule-based to ML-based.
type Correlator interface {
	// Correlate returns a list of device UUIDs historically linked to the given user.
	Correlate(userID string) []string

	// Record associates a device with a user when a connection is established.
	Record(userID, deviceUUID string)

	// RiskScore returns a risk score (0.0-1.0) for a device based on its cross-device behavior.
	RiskScore(deviceUUID string, history []*types.ConnectionSummary) float64
}

// SimpleCorrelator is a rule-based implementation:
// tracks user->devices mapping in memory.
type SimpleCorrelator struct {
	mu          sync.RWMutex
	userDevices map[string]map[string]struct{} // userID -> set of deviceUUIDs
	deviceUsers map[string]map[string]struct{} // deviceUUID -> set of userIDs
}

func NewSimpleCorrelator() *SimpleCorrelator {
	return &SimpleCorrelator{
		userDevices: make(map[string]map[string]struct{}),
		deviceUsers: make(map[string]map[string]struct{}),
	}
}

func (c *SimpleCorrelator) Record(userID, deviceUUID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.userDevices[userID] == nil {
		c.userDevices[userID] = make(map[string]struct{})
	}
	c.userDevices[userID][deviceUUID] = struct{}{}

	if c.deviceUsers[deviceUUID] == nil {
		c.deviceUsers[deviceUUID] = make(map[string]struct{})
	}
	c.deviceUsers[deviceUUID][userID] = struct{}{}
}

func (c *SimpleCorrelator) Correlate(userID string) []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	devices := make([]string, 0)
	if set, ok := c.userDevices[userID]; ok {
		for d := range set {
			devices = append(devices, d)
		}
	}
	return devices
}

func (c *SimpleCorrelator) RiskScore(deviceUUID string, history []*types.ConnectionSummary) float64 {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Simple rule: more users sharing the same device = higher risk.
	if users, ok := c.deviceUsers[deviceUUID]; ok {
		n := len(users)
		if n == 1 {
			return 0.0
		}
		if n == 2 {
			return 0.5
		}
		return 1.0
	}
	return 0.0
}