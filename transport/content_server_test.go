package transport

import (
	"net"
	"strings"
	"testing"
)

func TestContentBaseURLRewritesUnspecifiedBindHost(t *testing.T) {
	addr, err := net.ResolveTCPAddr("tcp", "0.0.0.0:19080")
	if err != nil {
		t.Fatal(err)
	}
	baseURL := contentBaseURL("0.0.0.0", addr)
	if strings.Contains(baseURL, "0.0.0.0") {
		t.Fatalf("base URL should be dialable loopback, got %q", baseURL)
	}
	if baseURL != "http://127.0.0.1:19080" {
		t.Fatalf("base URL = %q", baseURL)
	}
}
