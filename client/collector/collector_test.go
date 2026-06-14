package collector

import (
	"strings"
	"testing"
)

func TestCollector_Record(t *testing.T) {
	c := NewCollector()
	c.Record("GET", "/api/vms/status")
	c.Record("DELETE", "/api/images/1")
	c.Record("GET", "/api/vms/running")
	if c.TotalEvents() != 3 {
		t.Fatalf("TotalEvents() = %d, want 3", c.TotalEvents())
	}
	if c.EventCount("GET /api/vms/status") != 1 {
		t.Errorf("EventCount = %d, want 1", c.EventCount("GET /api/vms/status"))
	}
}

func TestCollector_Events(t *testing.T) {
	c := NewCollector()
	c.Record("POST", "/api/vms/start")
	events := c.Events()
	if len(events) != 1 {
		t.Fatalf("Events() len = %d, want 1", len(events))
	}
	if events[0].OpType != "POST /api/vms/start" {
		t.Errorf("OpType = %s, want POST /api/vms/start", events[0].OpType)
	}
}

func TestCollector_OpTag(t *testing.T) {
	c := NewCollector()
	c.Record("GET", "/api/vms/status")
	c.Record("GET", "/api/vms/running")
	c.Record("DELETE", "/api/images/1")
	tag := c.OpTag()
	parts := strings.Split(tag, ":")
	if len(parts) != 4 {
		t.Fatalf("OpTag() = %s, want 4 parts", tag)
	}
	if parts[0] != "3" {
		t.Errorf("total = %s, want 3", parts[0])
	}
}

func TestCollector_Reset(t *testing.T) {
	c := NewCollector()
	c.Record("GET", "/api/vms/status")
	c.Reset()
	if c.TotalEvents() != 0 {
		t.Errorf("after Reset TotalEvents() = %d, want 0", c.TotalEvents())
	}
}

func TestCollector_EmptyOpTag(t *testing.T) {
	c := NewCollector()
	tag := c.OpTag()
	if tag != "0:0:0:" {
		t.Errorf("empty OpTag() = %s, want 0:0:0:", tag)
	}
}