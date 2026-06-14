package alert

import (
	"testing"
	"time"

	"Threshold/pkg/types"
)

func TestAlertQueue_PutAndDrain(t *testing.T) {
	q := NewAlertQueue()

	entry1 := AlertEntry{
		Request:  &types.ParsedRequest{ConnectionID: "c1"},
		Decision: &types.Decision{Action: types.BLOCK},
	}
	entry2 := AlertEntry{
		Request:  &types.ParsedRequest{ConnectionID: "c2"},
		Decision: &types.Decision{Action: types.ALERT},
	}

	q.Put(entry1)
	q.Put(entry2)

	if q.Len() != 2 {
		t.Errorf("Len() = %d, want 2", q.Len())
	}

	entries := q.Drain()
	if len(entries) != 2 {
		t.Fatalf("Drain() got %d entries, want 2", len(entries))
	}
	if entries[0].Request.ConnectionID != "c1" {
		t.Errorf("entries[0].ConnectionID = %q, want c1", entries[0].Request.ConnectionID)
	}

	if q.Len() != 0 {
		t.Errorf("after Drain(), Len() = %d, want 0", q.Len())
	}
}

func TestAlertQueue_DrainEmpty(t *testing.T) {
	q := NewAlertQueue()
	entries := q.Drain()
	if len(entries) != 0 {
		t.Errorf("Drain() on empty queue got %d entries, want 0", len(entries))
	}
}

func TestAlertQueue_Subscribe(t *testing.T) {
	q := NewAlertQueue()
	ch := q.Subscribe("sub1")
	defer q.Unsubscribe("sub1")

	q.Put(AlertEntry{
		Request:  &types.ParsedRequest{ConnectionID: "c1"},
		Decision: &types.Decision{Action: types.BLOCK},
	})

	select {
	case entry := <-ch:
		if entry.Request.ConnectionID != "c1" {
			t.Errorf("subscriber got ConnectionID = %q, want c1", entry.Request.ConnectionID)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("subscriber did not receive alert notification")
	}
}

func TestAlertQueue_SubscribeMultiple(t *testing.T) {
	q := NewAlertQueue()
	ch1 := q.Subscribe("sub1")
	ch2 := q.Subscribe("sub2")
	defer q.Unsubscribe("sub1")
	defer q.Unsubscribe("sub2")

	q.Put(AlertEntry{
		Request:  &types.ParsedRequest{ConnectionID: "c1"},
		Decision: &types.Decision{Action: types.BLACKLIST_DEVICE},
	})

	received := 0
	for _, ch := range []<-chan AlertEntry{ch1, ch2} {
		select {
		case <-ch:
			received++
		case <-time.After(100 * time.Millisecond):
		}
	}
	if received != 2 {
		t.Errorf("received %d notifications, want 2", received)
	}
}

func TestAlertQueue_Unsubscribe(t *testing.T) {
	q := NewAlertQueue()
	ch := q.Subscribe("sub1")
	q.Unsubscribe("sub1")

	q.Put(AlertEntry{
		Request:  &types.ParsedRequest{ConnectionID: "c1"},
		Decision: &types.Decision{Action: types.BLOCK},
	})

	select {
	case <-ch:
		t.Error("unsubscribed channel should not receive notifications")
	default:
		// expected
	}
}
