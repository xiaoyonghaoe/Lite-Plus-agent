package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	v2 "github.com/nuomiiiii/lite-agent/protocol/v2"
)

func configureAccessTest(t *testing.T, endpoint, clientID, clientSecret string) {
	t.Helper()
	originalEndpoint := flags.Endpoint
	originalToken := flags.Token
	originalID := flags.CFAccessClientID
	originalSecret := flags.CFAccessClientSecret
	originalCompression := flags.DisableCompression
	originalRetries := flags.MaxRetries
	flags.Endpoint = endpoint
	flags.Token = "agent-token"
	flags.CFAccessClientID = clientID
	flags.CFAccessClientSecret = clientSecret
	flags.DisableCompression = true
	flags.MaxRetries = 0
	t.Cleanup(func() {
		flags.Endpoint = originalEndpoint
		flags.Token = originalToken
		flags.CFAccessClientID = originalID
		flags.CFAccessClientSecret = originalSecret
		flags.DisableCompression = originalCompression
		flags.MaxRetries = originalRetries
	})
}

func requireAccessHeaders(request *http.Request) bool {
	return request.Header.Get("Authorization") == "Bearer agent-token" &&
		request.Header.Get("CF-Access-Client-Id") == "access-id" &&
		request.Header.Get("CF-Access-Client-Secret") == "access-secret"
}

func TestAgentAuthorizationUsesHeader(t *testing.T) {
	configureAccessTest(t, "", "access-id", "access-secret")
	request, err := http.NewRequest(http.MethodPost, "https://example.com/api/clients/v2/rpc", nil)
	if err != nil {
		t.Fatal(err)
	}
	authorizeAgentRequest(request, "secret-token")
	if got := request.Header.Get("Authorization"); got != "Bearer secret-token" {
		t.Fatalf("unexpected Authorization header: %q", got)
	}
	if got := request.Header.Get("CF-Access-Client-Id"); got != "access-id" {
		t.Fatalf("unexpected Cloudflare Access client ID: %q", got)
	}
	if got := request.Header.Get("CF-Access-Client-Secret"); got != "access-secret" {
		t.Fatalf("unexpected Cloudflare Access client secret: %q", got)
	}
	if request.URL.RawQuery != "" {
		t.Fatalf("agent credential leaked into query: %q", request.URL.RawQuery)
	}
}

func TestCloudflareAccessProtectedAgentHTTPFlows(t *testing.T) {
	seen := make(map[string]int)
	srv := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !requireAccessHeaders(request) {
			http.Error(writer, "Cloudflare Access denied", http.StatusForbidden)
			return
		}
		if request.URL.RawQuery != "" {
			t.Errorf("credential-bearing query remains on %s: %q", request.URL.Path, request.URL.RawQuery)
		}
		seen[request.URL.Path]++
		writer.WriteHeader(http.StatusOK)
		if request.URL.Path == "/api/clients/v2/rpc" {
			_ = json.NewEncoder(writer).Encode(v2.Response{JSONRPC: v2.Version, ID: "access-test", Result: map[string]string{"status": "ok"}})
		}
	}))
	t.Cleanup(srv.Close)
	configureAccessTest(t, srv.URL, "", "")

	if err := tryUploadData(map[string]interface{}{"name": "test"}); err == nil {
		t.Fatal("HTTP request unexpectedly passed Cloudflare Access without service-token headers")
	}
	flags.CFAccessClientID = "access-id"
	flags.CFAccessClientSecret = "access-secret"

	if err := tryUploadData(map[string]interface{}{"name": "test"}); err != nil {
		t.Fatalf("v2 basic info failed: %v", err)
	}
	if _, err := postV2Request(v2.BuildReportRequest("access-test", []byte(`{}`), nil)); err != nil {
		t.Fatalf("v2 report POST failed: %v", err)
	}

	if seen["/api/clients/v2/rpc"] != 2 {
		t.Fatalf("v2 POST requests = %d, want 2", seen["/api/clients/v2/rpc"])
	}
}
