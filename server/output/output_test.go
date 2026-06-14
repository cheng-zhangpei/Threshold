package output

import (
	"testing"
	"time"

	"Threshold/pkg/types"
)

func TestOutputBuffer_PutAndPull(t *testing.T) {
	buf := NewOutputBuffer()

	msg1 := Message{
		Request:  &types.ParsedRequest{ConnectionID: "c1"},
		Decision: &types.Decision{Action: types.ALLOW},
	}
	msg2 := Message{
		Request:  &types.ParsedRequest{ConnectionID: "c2"},
		Decision: &types.Decision{Action: types.ALLOW},
	}

	buf.Put(msg1)
	buf.Put(msg2)

	if buf.Len() != 2 {
		t.Errorf("Len() = %d, want 2", buf.Len())
	}

	msgs := buf.Pull()
	if len(msgs) != 2 {
		t.Fatalf("Pull() got %d messages, want 2", len(msgs))
	}
	if msgs[0].Request.ConnectionID != "c1" {
		t.Errorf("msgs[0].ConnectionID = %q, want c1", msgs[0].Request.ConnectionID)
	}
	if msgs[1].Request.ConnectionID != "c2" {
		t.Errorf("msgs[1].ConnectionID = %q, want c2", msgs[1].Request.ConnectionID)
	}

	if buf.Len() != 0 {
		t.Errorf("after Pull(), Len() = %d, want 0", buf.Len())
	}
}

func TestOutputBuffer_PullEmpty(t *testing.T) {
	buf := NewOutputBuffer()
	msgs := buf.Pull()
	if len(msgs) != 0 {
		t.Errorf("Pull() on empty buffer got %d messages, want 0", len(msgs))
	}
}

func TestOutputBuffer_MaxSizeEviction(t *testing.T) {
	buf := NewOutputBufferWithMaxSize(3)

	for i := 0; i < 5; i++ {
		buf.Put(Message{
			Request:  &types.ParsedRequest{ConnectionID: string(rune('a' + i))},
			Decision: &types.Decision{Action: types.ALLOW},
		})
	}

	if buf.Len() != 3 {
		t.Errorf("Len() = %d, want 3", buf.Len())
	}

	msgs := buf.Pull()
	if msgs[0].Request.ConnectionID != "c" {
		t.Errorf("first message ConnectionID = %q, want c (oldest evicted)", msgs[0].Request.ConnectionID)
	}
}

func TestOutputBuffer_Subscribe(t *testing.T) {
	buf := NewOutputBuffer()
	ch := buf.Subscribe()
	defer buf.Unsubscribe(ch)

	buf.Put(Message{
		Request:  &types.ParsedRequest{ConnectionID: "c1"},
		Decision: &types.Decision{Action: types.ALLOW},
	})

	select {
	case <-ch:
		// ok
	case <-time.After(100 * time.Millisecond):
		t.Error("subscriber did not receive notification")
	}
}

func TestOutputBuffer_SubscribeNoBlock(t *testing.T) {
	buf := NewOutputBuffer()
	ch := buf.Subscribe()
	defer buf.Unsubscribe(ch)

	for i := 0; i < 10; i++ {
		buf.Put(Message{
			Request:  &types.ParsedRequest{ConnectionID: "c1"},
			Decision: &types.Decision{Action: types.ALLOW},
		})
	}

	select {
	case <-ch:
		// ok - notification received (may be coalesced)
	default:
		// also ok - notification channel non-blocking
	}
}
