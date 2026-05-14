package fofa

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

const fixtureOK = `{
  "error": false,
  "size": 4,
  "page": 1,
  "results": [
    ["sub.example.com:443", "1.2.3.4", "443"],
    ["https://api.example.com:8443", "5.6.7.8", "8443"],
    ["mail.example.com", "9.10.11.12", "25"],
    ["API.Example.COM:80", "1.2.3.4", "80"]
  ]
}`

const fixtureError = `{"error":true,"errmsg":"[820001] quota exceeded"}`

func TestParseResponse_Happy(t *testing.T) {
	rows, err := ParseResponse([]byte(fixtureOK))
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	// sub / api / mail = 3；最后一行 "API.Example.COM" 归一为 api.example.com 与第二行重，去重
	if len(rows) != 3 {
		t.Fatalf("want 3 rows (dedup + strip port + lowercase), got %d: %+v", len(rows), rows)
	}
	if rows[0]["name"] != "sub.example.com" {
		t.Errorf("rows[0].name = %v want sub.example.com (port stripped)", rows[0]["name"])
	}
	if rows[0]["ip"] != "1.2.3.4" {
		t.Errorf("rows[0].ip = %v", rows[0]["ip"])
	}
	if rows[0]["port"] != "443" {
		t.Errorf("rows[0].port = %v", rows[0]["port"])
	}
	if rows[0]["source"] != "fofa" {
		t.Errorf("rows[0].source = %v", rows[0]["source"])
	}
	// rows[1]: scheme:// 剥掉 + port 剥掉
	if rows[1]["name"] != "api.example.com" {
		t.Errorf("rows[1].name = %v (scheme + port should be stripped)", rows[1]["name"])
	}
}

func TestParseResponse_ErrorResponse(t *testing.T) {
	_, err := ParseResponse([]byte(fixtureError))
	if err == nil {
		t.Fatal("want error on error=true")
	}
	if !strings.Contains(err.Error(), "quota exceeded") {
		t.Errorf("err missing errmsg: %v", err)
	}
}

func TestParseResponse_BadJSON(t *testing.T) {
	_, err := ParseResponse([]byte("not-json"))
	if err == nil {
		t.Fatal("want error on bad JSON")
	}
}

func TestParseResponse_EmptyResults(t *testing.T) {
	rows, err := ParseResponse([]byte(`{"error":false,"size":0,"results":[]}`))
	if err != nil {
		t.Fatalf("empty: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("want 0 rows, got %d", len(rows))
	}
}

func TestParseResponse_RespectsMaxSubdomains(t *testing.T) {
	orig := MaxSubdomains
	MaxSubdomains = 2
	defer func() { MaxSubdomains = orig }()
	in := `{"error":false,"results":[["a.example.com"],["b.example.com"],["c.example.com"],["d.example.com"]]}`
	rows, _ := ParseResponse([]byte(in))
	if len(rows) != 2 {
		t.Errorf("want 2 (max), got %d", len(rows))
	}
}

func TestParseResponse_RejectsIPLikeHost(t *testing.T) {
	// host 字段是 IP 时 hostRe 拒（仅入域名）
	in := `{"error":false,"results":[["192.0.2.1:80","192.0.2.1","80"],["good.example.com","1.2.3.4","443"]]}`
	rows, _ := ParseResponse([]byte(in))
	if len(rows) != 1 {
		t.Errorf("want 1 (skip IP host), got %d: %+v", len(rows), rows)
	}
	if rows[0]["name"] != "good.example.com" {
		t.Errorf("name = %v", rows[0]["name"])
	}
}

// === HTTP path ===

func TestRun_EndToEnd(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 验证 query params
		if r.URL.Query().Get("email") != "test@example.com" {
			t.Errorf("email = %v", r.URL.Query().Get("email"))
		}
		if r.URL.Query().Get("key") != "fake-key" {
			t.Errorf("key = %v", r.URL.Query().Get("key"))
		}
		qb64 := r.URL.Query().Get("qbase64")
		decoded, err := base64.StdEncoding.DecodeString(qb64)
		if err != nil {
			t.Errorf("qbase64 not valid base64: %v", err)
		}
		if string(decoded) != `domain="example.com"` {
			t.Errorf("query decoded = %q", string(decoded))
		}
		if r.URL.Query().Get("fields") != "host,ip,port" {
			t.Errorf("fields = %v", r.URL.Query().Get("fields"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, fixtureOK)
	}))
	defer server.Close()

	orig := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = orig }()

	p := &Plugin{
		email:  "test@example.com",
		key:    "fake-key",
		client: server.Client(),
	}
	rows, err := p.Run(context.Background(), "example.com", "host", nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(rows) != 3 {
		t.Errorf("want 3 (e2e same as ParseResponse_Happy), got %d", len(rows))
	}
}

func TestRun_NonOKStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, "invalid key")
	}))
	defer server.Close()

	orig := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = orig }()

	p := &Plugin{email: "x@x", key: "x", client: server.Client()}
	_, err := p.Run(context.Background(), "example.com", "host", nil)
	if err == nil {
		t.Fatal("want error on 401")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("err missing status: %v", err)
	}
}

func TestRun_RejectsNonHost(t *testing.T) {
	p := &Plugin{email: "x@x", key: "x", client: http.DefaultClient}
	_, err := p.Run(context.Background(), "192.0.2.1", "ip", nil)
	if err == nil {
		t.Fatal("want error on target_kind=ip")
	}
}

func TestNew_MissingEnv(t *testing.T) {
	// 临时清掉 env（如果有），验证 ErrNotInstalled
	origEmail := os.Getenv("FOFA_EMAIL")
	origKey := os.Getenv("FOFA_KEY")
	_ = os.Unsetenv("FOFA_EMAIL")
	_ = os.Unsetenv("FOFA_KEY")
	defer func() {
		_ = os.Setenv("FOFA_EMAIL", origEmail)
		_ = os.Setenv("FOFA_KEY", origKey)
	}()

	_, err := New()
	if err == nil {
		t.Fatal("want ErrNotInstalled when env missing")
	}
}

func TestNew_BothEnvSet(t *testing.T) {
	origEmail := os.Getenv("FOFA_EMAIL")
	origKey := os.Getenv("FOFA_KEY")
	_ = os.Setenv("FOFA_EMAIL", "t@t.com")
	_ = os.Setenv("FOFA_KEY", "abc")
	defer func() {
		_ = os.Setenv("FOFA_EMAIL", origEmail)
		_ = os.Setenv("FOFA_KEY", origKey)
	}()

	p, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if p.email != "t@t.com" || p.key != "abc" {
		t.Errorf("env not loaded: email=%v key=%v", p.email, p.key)
	}
}

func TestKindAndMockFlags(t *testing.T) {
	p := &Plugin{}
	if p.Kind() != "subdomain" {
		t.Errorf("Kind = %q, want subdomain", p.Kind())
	}
	if p.IsMock() {
		t.Errorf("IsMock = true, want false")
	}
}
