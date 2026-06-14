package crossdevice

import (
	"sort"
	"testing"
)

func TestSimpleCorrelator_RecordAndCorrelate(t *testing.T) {
	c := NewSimpleCorrelator()
	c.Record("user-1", "device-a")
	c.Record("user-1", "device-b")
	devices := c.Correlate("user-1")
	sort.Strings(devices)
	if len(devices) != 2 || devices[0] != "device-a" || devices[1] != "device-b" {
		t.Errorf("Correlate() = %v, want [device-a device-b]", devices)
	}
}

func TestSimpleCorrelator_CorrelateEmpty(t *testing.T) {
	c := NewSimpleCorrelator()
	devices := c.Correlate("unknown-user")
	if len(devices) != 0 {
		t.Errorf("Correlate() = %v, want empty", devices)
	}
}

func TestSimpleCorrelator_RiskScore_SingleUser(t *testing.T) {
	c := NewSimpleCorrelator()
	c.Record("user-1", "device-a")
	score := c.RiskScore("device-a", nil)
	if score != 0.0 {
		t.Errorf("RiskScore() = %f, want 0.0", score)
	}
}

func TestSimpleCorrelator_RiskScore_TwoUsers(t *testing.T) {
	c := NewSimpleCorrelator()
	c.Record("user-1", "device-a")
	c.Record("user-2", "device-a")
	score := c.RiskScore("device-a", nil)
	if score != 0.5 {
		t.Errorf("RiskScore() = %f, want 0.5", score)
	}
}

func TestSimpleCorrelator_RiskScore_ManyUsers(t *testing.T) {
	c := NewSimpleCorrelator()
	c.Record("user-1", "device-a")
	c.Record("user-2", "device-a")
	c.Record("user-3", "device-a")
	score := c.RiskScore("device-a", nil)
	if score != 1.0 {
		t.Errorf("RiskScore() = %f, want 1.0", score)
	}
}

func TestSimpleCorrelator_RiskScore_UnknownDevice(t *testing.T) {
	c := NewSimpleCorrelator()
	score := c.RiskScore("unknown", nil)
	if score != 0.0 {
		t.Errorf("RiskScore() = %f, want 0.0", score)
	}
}
