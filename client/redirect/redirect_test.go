package redirect

import (
	"testing"
)

func TestNew(t *testing.T) {
	m := New(8080, "localhost", 50051)
	if m.localPort != 8080 {
		t.Errorf("localPort = %d, want 8080", m.localPort)
	}
}

func TestValidatePort_Available(t *testing.T) {
	if !ValidatePort(19876) {
		t.Error("ValidatePort should return true for available port")
	}
}

func TestParseHTTPMethod(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"GET /api/vms HTTP/1.1", "GET"},
		{"DELETE /api/images/1 HTTP/1.1", "DELETE"},
		{"", ""},
	}
	for _, tt := range tests {
		got := ParseHTTPMethod([]byte(tt.input))
		if got != tt.want {
			t.Errorf("ParseHTTPMethod(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}