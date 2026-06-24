package grpc

import (
	"Threshold/pkg/storage"
	"Threshold/pkg/waiter"
	"Threshold/server/admin"
	"Threshold/server/dispatch"
	"Threshold/server/router/router_v1"
	"Threshold/server/router/router_v2"
	"Threshold/server/token"
	"crypto/tls"
	"fmt"
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"Threshold/pkg/config"
	pb "Threshold/pkg/proto/pb"
	"Threshold/server/alert"
	"Threshold/server/decision"
	"Threshold/server/fingerprint"
	"Threshold/server/output"
	"Threshold/server/portrait"
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
	r *router_v1.Router,
	r2 *router_v2.Router,
	outputBuf *output.OutputBuffer,
	alertQueue *alert.AlertQueue,
	portraitStore *portrait.Store,
	waiter *waiter.Waiter,
	dm *dispatch.DispatchManager,
	db *storage.BoltStore,
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
			log.Printf("Failed to load TLS credentials: %v", err)
			return nil, fmt.Errorf("load tls: %w", err)
		}
		opts = append(opts, grpc.Creds(creds))
	}
	grpcServer := grpc.NewServer(opts...)
	adminStore, err := admin.NewStore(db)
	if err != nil {
		log.Fatalf("init admin store: %v", err)
	}

	tokenStore, err := token.NewStore(db, "")
	if err != nil {
		log.Fatalf("init token store: %v", err)
	}
	// 检查是否已有管理员
	if !adminStore.HasAdmin() {
		// 生成一次性口令
		passcode, err := admin.GeneratePasscode("./data")
		if err != nil {
			log.Fatalf("generate passcode: %v", err)
		}
		fmt.Println("========================================")
		fmt.Println("  Admin not initialized.")
		fmt.Printf("  One-time passcode: %s\n", passcode)
		fmt.Println("  Run: adminctl init -passcode <code> -user admin -pass <password>")
		fmt.Println("========================================")
	} else {
		fmt.Println("Admin already initialized.")
	}
	handler := NewHandler(fpTree, engine, r, r2, outputBuf, alertQueue, portraitStore, waiter, dm, adminStore, tokenStore)
	pb.RegisterSecurityProxyServer(grpcServer, handler)

	listener, err := net.Listen("tcp", cfg.GRPC.ListenAddr)
	if err != nil {
		log.Printf("failed to listen: %v", err)
		return nil, fmt.Errorf("listen: %w", err)
	}

	return &Server{grpcServer: grpcServer, listener: listener, handler: handler, limiter: limiter}, nil
}

func (s *Server) Start() error  { return s.grpcServer.Serve(s.listener) }
func (s *Server) GracefulStop() { s.grpcServer.GracefulStop() }

func loadTLSCredentials(cfg config.TLSConfig) (credentials.TransportCredentials, error) {
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		log.Printf("Failed to load TLS certificates: %v", err)
		return nil, fmt.Errorf("load certs: %w", err)
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	if cfg.RequireClientAuth {
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return credentials.NewTLS(tlsCfg), nil
}
