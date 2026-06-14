package collector

import (
	"fmt"
	"sync"
	"time"
)

// Event represents a single recorded operation.
type Event struct {
	OpType    string
	Method    string
	Path      string
	Timestamp time.Time
}

// Collector records events for the current connection.
// Thread-safe: safe for concurrent use by proxy handlers.
type Collector struct {
	mu     sync.Mutex
	events []Event
	counts map[string]int
}

// NewCollector creates a fresh collector for a new connection.
func NewCollector() *Collector {
	return &Collector{
		counts: make(map[string]int),
	}
}

// Record appends an event and updates the op count.
func (c *Collector) Record(method, path string) {
	opType := method + " " + path
	c.mu.Lock()
	c.events = append(c.events, Event{
		OpType:    opType,
		Method:    method,
		Path:      path,
		Timestamp: time.Now(),
	})
	c.counts[opType]++
	c.mu.Unlock()
}

// Events returns a copy of the recorded events.
func (c *Collector) Events() []Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Event, len(c.events))
	copy(out, c.events)
	return out
}

// EventCount returns the count for a given opType.
func (c *Collector) EventCount(opType string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.counts[opType]
}

// TotalEvents returns the total number of recorded events.
func (c *Collector) TotalEvents() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.events)
}

// OpTag generates a summary tag for the current connection state.
// Format: total_events:write_count:read_count:last_op
func (c *Collector) OpTag() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	total := len(c.events)
	reads := 0
	writes := 0
	for op, cnt := range c.counts {
		if op == "GET " || op[:4] == "GET " {
			reads += cnt
		} else {
			writes += cnt
		}
	}
	lastOp := ""
	if total > 0 {
		lastOp = c.events[total-1].OpType
	}
	return fmt.Sprintf("%d:%d:%d:%s", total, writes, reads, lastOp)
}

// Reset clears all recorded events for a new connection.
func (c *Collector) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = c.events[:0]
	c.counts = make(map[string]int)
}
