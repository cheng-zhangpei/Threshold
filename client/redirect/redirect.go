package redirect

import (
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"strings"
)

type Module struct {
	localPort  int
	targetHost string
	targetPort int
}

func New(localPort int, targetHost string, targetPort int) *Module {
	return &Module{localPort: localPort, targetHost: targetHost, targetPort: targetPort}
}

func (m *Module) Setup() error {
	switch runtime.GOOS {
	case "linux", "darwin":
		return m.setupProxychains()
	case "windows":
		return m.setupPAC()
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

func (m *Module) setupProxychains() error {
	cfgPath := "/tmp/threshold_proxychains.conf"
	var sb strings.Builder
	for _, line := range []string{"strict_chain", "proxy_dns", "[ProxyList]"} {
		sb.WriteString(line)
		sb.WriteByte(10)
	}
	fmt.Fprintf(&sb, "socks5 127.0.0.1 %d", m.localPort)
	sb.WriteByte(10)
	if err := os.WriteFile(cfgPath, []byte(sb.String()), 0644); err != nil {
		return fmt.Errorf("write proxychains config: %w", err)
	}
	log.Printf("[REDIRECT] proxychains config written to %s", cfgPath)
	fmt.Println("[REDIRECT] usage: proxychains4 <your-command>")
	return nil
}

func (m *Module) setupPAC() error { // TODO: PAC template needs manual fix for escaped quotes
	_ = m
	return nil
}

func (m *Module) Teardown() {
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		os.Remove("/tmp/threshold_proxychains.conf")
	}
	os.Remove("threshold_proxy.pac")
	log.Printf("[REDIRECT] teardown complete")
}

func ValidatePort(port int) bool {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return false
	}
	ln.Close()
	return true
}

func ParseHTTPMethod(rawRequest []byte) string {
	line := string(rawRequest)
	idx := strings.IndexByte(line, byte(' '))
	if idx < 0 {
		return ""
	}
	return strings.ToUpper(line[:idx])
}
