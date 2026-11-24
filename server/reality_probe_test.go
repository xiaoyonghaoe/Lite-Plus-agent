package server

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProbeRealityTargetLocalTLS13(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h2", "http/1.1"},
	}
	srv.StartTLS()
	defer srv.Close()

	addr := strings.TrimPrefix(srv.URL, "https://")
	res := ProbeRealityTarget(context.Background(), addr, "example.com")
	if !res.Reachable || !res.Local || !res.TLS13 || !res.OK {
		t.Fatalf("expected reachable local TLS1.3 OK, got %+v", res)
	}
	if res.TLSVersion != "TLS 1.3" {
		t.Fatalf("unexpected TLSVersion: %q", res.TLSVersion)
	}
}
