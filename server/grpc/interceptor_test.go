package grpc

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestUnaryInterceptor_AllowsNormal(t *testing.T) {
	limiter := NewTokenBucket(1000, 1000)
	interceptor := UnaryServerInterceptor(limiter)
	called := false
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		called = true
		return "ok", nil
	}
	resp, err := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/scripts/Method"}, handler)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Error("handler not called")
	}
	if resp != "ok" {
		t.Errorf("resp = %v, want ok", resp)
	}
}

func TestUnaryInterceptor_RateLimit(t *testing.T) {
	limiter := NewTokenBucket(1, 1)
	limiter.Allow() // exhaust
	interceptor := UnaryServerInterceptor(limiter)
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		t.Error("handler should not be called")
		return nil, nil
	}
	_, err := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/scripts/Method"}, handler)
	if err == nil {
		t.Fatal("expected rate limit error")
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.ResourceExhausted {
		t.Errorf("code = %v, want ResourceExhausted", st.Code())
	}
}

func TestUnaryInterceptor_NilLimiter(t *testing.T) {
	interceptor := UnaryServerInterceptor(nil)
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return "ok", nil
	}
	resp, err := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/scripts"}, handler)
	if err != nil || resp != "ok" {
		t.Errorf("nil limiter should pass through: resp=%v err=%v", resp, err)
	}
}

func TestUnaryInterceptor_PanicRecovery(t *testing.T) {
	limiter := NewTokenBucket(1000, 1000)
	interceptor := UnaryServerInterceptor(limiter)
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		panic("boom")
	}
	resp, err := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/scripts"}, handler)
	if resp != nil {
		t.Errorf("resp = %v, want nil", resp)
	}
	if err == nil {
		t.Fatal("expected error from panic recovery")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.Internal {
		t.Errorf("code = %v, want Internal", st.Code())
	}
}
