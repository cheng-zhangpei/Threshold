package grpc

import (
	"crypto/tls"
	"fmt"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"Threshold/pkg/config"
	"Threshold/server/alert"
	"Threshold/server/decision"
	"Threshold/server/fingerprint"
	"Threshold/server/output"
	"Threshold/server/portrait"
	"Threshold/server/router"

	pb "Threshold/pkg/proto/pb"
)

type Server struct {
	grpcServer *grpc.Server
	listener   net.Listener
	handler    *Handler
	limiter    *TokenBucket
}

func New(
	cfg *config.ServerConfig,
	fpTree *fingerprint.Tree,
	engine *decision.Engine,
	r *router.Router,
	outputBuf *output.OutputBuffer,
	alertQueue *alert.AlertQueue,
	portraitStore *portrait.Store,
) (*Server, error) {
	var opts []grpc.ServerOption

	limiter := NewTokenBucket(float64(cfg.GRPC.RateLimit), cfg.GRPC.BucketSize)
	opts = append(opts,
		grpc.UnaryInterceptor(UnaryServerInterceptor(limiter)),
		grpc.StreamInterceptor(StreamServerInterceptor(limiter)),
	)

	if cfg.TLS.Enabled {
		creds, err := loadTLSCredentials(cfg.TLS)
		if err != nil {
			return nil, fmt.Errorf("load tls: %w", err)
		}
		opts = append(opts, grpc.Creds(creds))
	}

	grpcServer := grpc.NewServer(opts...)
	handler := NewHandler(fpTree, engine, r, outputBuf, alertQueue, portraitStore)
	pb.RegisterSecurityProxyServer(grpcServer, handler)

	listener, err := net.Listen("tcp", cfg.GRPC.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}

	return &Server{grpcServer: grpcServer, listener: listener, handler: handler, limiter: limiter}, nil
}

func (s *Server) Start() error  { return s.grpcServer.Serve(s.listener) }
func (s *Server) GracefulStop() { s.grpcServer.GracefulStop() }

func loadTLSCredentials(cfg config.TLSConfig) (credentials.TransportCredentials, error) {
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load cert: %w", err)
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	if cfg.RequireClientAuth {
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return credentials.NewTLS(tlsCfg), nil
}