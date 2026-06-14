package grpc

import (
	"context"
	"log"
	"runtime/debug"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// UnaryServerInterceptor returns a chained unary interceptor: rate limit + recovery + logging.
func UnaryServerInterceptor(limiter *TokenBucket) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
		) (resp interface{}, err error) {
		start := time.Now()
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[RECOVERY] %s panic: %v\n%s", info.FullMethod, r, debug.Stack())
				resp = nil
				err = status.Errorf(codes.Internal, "internal server error")
			}
			log.Printf("[RPC] %s %v %s", info.FullMethod, time.Since(start), peerAddr(ctx))
		}()

		if limiter != nil && !limiter.Allow() {
			return nil, status.Errorf(codes.ResourceExhausted, "rate limit exceeded")
		}

		return handler(ctx, req)
	}
}

// StreamServerInterceptor returns a chained stream interceptor: rate limit + recovery + logging.
func StreamServerInterceptor(limiter *TokenBucket) grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
		) (ret error) {
		start := time.Now()
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[RECOVERY] %s stream panic: %v\n%s", info.FullMethod, r, debug.Stack())
				ret = status.Errorf(codes.Internal, "internal server error")
			}
			log.Printf("[STREAM] %s %v %s", info.FullMethod, time.Since(start), peerAddr(ss.Context()))
		}()

		if limiter != nil && !limiter.Allow() {
			return status.Errorf(codes.ResourceExhausted, "rate limit exceeded")
		}

		return handler(srv, ss)
	}
}

func peerAddr(ctx context.Context) string {
	if p, ok := peer.FromContext(ctx); ok {
		return p.Addr.String()
	}
	return "unknown"
}