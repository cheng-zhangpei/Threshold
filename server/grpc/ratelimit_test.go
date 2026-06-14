package grpc

import (
	"testing"
	"time"
)

func TestTokenBucket_Allow(t *testing.T) {
	tb := NewTokenBucket(10, 10)
	for i := 0; i < 10; i++ {
		if !tb.Allow() {
			t.Fatalf("Allow() = false at iteration %d, want true", i)
		}
	}
	if tb.Allow() {
		t.Error("Allow() = true after burst exhausted, want false")
	}
}

func TestTokenBucket_Refill(t *testing.T) {
	tb := NewTokenBucket(100, 5)
	// Exhaust all tokens
	for i := 0; i < 5; i++ {
		tb.Allow()
	}
	time.Sleep(60 * time.Millisecond)
	// Should have refilled ~6 tokens (100 * 0.06), capped at burst=5
	if !tb.Allow() {
		t.Error("Allow() = false after refill, want true")
	}
}

func TestTokenBucket_AllowN(t *testing.T) {
	tb := NewTokenBucket(10, 10)
	if !tb.AllowN(5) {
		t.Error("AllowN(5) = false, want true")
	}
	if !tb.AllowN(5) {
		t.Error("AllowN(5) = false, want true")
	}
	if tb.AllowN(1) {
		t.Error("AllowN(1) = true after exhaustion, want false")
	}
}

func TestTokenBucket_Tokens(t *testing.T) {
	tb := NewTokenBucket(10, 10)
	tok := tb.Tokens()
	if tok < 9.0 || tok > 10.0 {
		t.Errorf("Tokens() = %f, want ~10", tok)
	}
}

func TestTokenBucket_RateBurst(t *testing.T) {
	tb := NewTokenBucket(50, 20)
	if tb.Rate() != 50 {
		t.Errorf("Rate() = %f, want 50", tb.Rate())
	}
	if tb.Burst() != 20 {
		t.Errorf("Burst() = %d, want 20", tb.Burst())
	}
}

func TestTokenBucket_Concurrent(t *testing.T) {
	tb := NewTokenBucket(1000, 1000)
	done := make(chan struct{}, 100)
	for i := 0; i < 100; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				tb.Allow()
			}
			done <- struct{}{}
		}()
	}
	for i := 0; i < 100; i++ {
		<-done
	}
	// No race = pass. Tokens should be near 0 or refilled.
}
