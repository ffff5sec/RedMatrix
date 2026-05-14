package crtsh

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const fixtureJSON = `[
  {"issuer_ca_id":1,"name_value":"api.example.com\nwww.example.com"},
  {"issuer_ca_id":2,"name_value":"mail.example.com"},
  {"issuer_ca_id":3,"name_value":"*.example.com\napi.example.com"},
  {"issuer_ca_id":4,"name_value":"API.Example.COM"}
]`

func TestParseResponse_Happy(t *testing.T) {
	rows, err := ParseResponse([]byte(fixtureJSON))
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	// api / www / mail = 3；通配符 *.example.com 跳过；重复 api 去重
	if len(rows) != 3 {
		t.Fatalf("want 3 rows (dedup + skip wildcard + lowercase), got %d: %+v", len(rows), rows)
	}
	if rows[0]["name"] != "api.example.com" {
		t.Errorf("rows[0].name = %v", rows[0]["name"])
	}
	if rows[0]["source"] != "crtsh" {
		t.Errorf("rows[0].source = %v", rows[0]["source"])
	}
	if rows[2]["name"] != "mail.example.com" {
		t.Errorf("rows[2].name = %v", rows[2]["name"])
	}
}

func TestParseResponse_SAN_MultilineExpanded(t *testing.T) {
	in := `[{"name_value":"a.example.com\nb.example.com\nc.example.com"}]`
	rows, _ := ParseResponse([]byte(in))
	if len(rows) != 3 {
		t.Errorf("want 3 (SAN multiline), got %d", len(rows))
	}
}

func TestParseResponse_WildcardSkipped(t *testing.T) {
	in := `[{"name_value":"*.example.com"},{"name_value":"good.example.com"}]`
	rows, _ := ParseResponse([]byte(in))
	if len(rows) != 1 {
		t.Errorf("want 1 (skip wildcard), got %d: %+v", len(rows), rows)
	}
	if rows[0]["name"] != "good.example.com" {
		t.Errorf("name = %v", rows[0]["name"])
	}
}

func TestParseResponse_HostLowercased(t *testing.T) {
	in := `[{"name_value":"API.Example.COM"}]`
	rows, _ := ParseResponse([]byte(in))
	if len(rows) != 1 {
		t.Fatalf("want 1, got %d", len(rows))
	}
	if rows[0]["name"] != "api.example.com" {
		t.Errorf("name not lowercased: %v", rows[0]["name"])
	}
}

func TestParseResponse_Empty(t *testing.T) {
	rows, err := ParseResponse([]byte("[]"))
	if err != nil {
		t.Fatalf("empty: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("want 0, got %d", len(rows))
	}
}

func TestParseResponse_BadJSON(t *testing.T) {
	_, err := ParseResponse([]byte("not-json"))
	if err == nil {
		t.Fatal("want error on non-JSON response (crt.sh sometimes returns HTML error page)")
	}
}

func TestParseResponse_RespectsMaxSubdomains(t *testing.T) {
	orig := MaxSubdomains
	MaxSubdomains = 2
	defer func() { MaxSubdomains = orig }()
	in := `[{"name_value":"a.example.com\nb.example.com\nc.example.com\nd.example.com"}]`
	rows, _ := ParseResponse([]byte(in))
	if len(rows) != 2 {
		t.Errorf("want 2 (max), got %d", len(rows))
	}
}

// === HTTP path: 端到端走 httptest server ===

func TestRun_EndToEnd(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("q") != "%.example.com" {
			t.Errorf("query q=%q want %%.example.com", r.URL.Query().Get("q"))
		}
		if r.URL.Query().Get("output") != "json" {
			t.Errorf("query output=%q want json", r.URL.Query().Get("output"))
		}
		if !strings.HasPrefix(r.Header.Get("User-Agent"), "RedMatrix/") {
			t.Errorf("UA = %v want RedMatrix prefix", r.Header.Get("User-Agent"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, fixtureJSON)
	}))
	defer server.Close()

	orig := apiBaseURL
	apiBaseURL = server.URL + "/"
	defer func() { apiBaseURL = orig }()

	p, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
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
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, "upstream down")
	}))
	defer server.Close()

	orig := apiBaseURL
	apiBaseURL = server.URL + "/"
	defer func() { apiBaseURL = orig }()

	p, _ := New()
	_, err := p.Run(context.Background(), "example.com", "host", nil)
	if err == nil {
		t.Fatal("want error on 502")
	}
	if !strings.Contains(err.Error(), "502") {
		t.Errorf("err missing status code: %v", err)
	}
}

func TestRun_RejectsNonHost(t *testing.T) {
	p, _ := New()
	_, err := p.Run(context.Background(), "192.0.2.1", "ip", nil)
	if err == nil {
		t.Fatal("want error on target_kind=ip")
	}
}

func TestRun_RejectsBadTarget(t *testing.T) {
	p, _ := New()
	_, err := p.Run(context.Background(), "-bad.example.com", "host", nil)
	if err == nil {
		t.Fatal("want error on hyphen-leading host (safetarget)")
	}
}

func TestRun_ContextCanceled(t *testing.T) {
	// 服务端故意延迟，让 ctx cancel 前 client 还没拿到响应
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		_, _ = io.WriteString(w, "[]")
	}))
	defer server.Close()

	orig := apiBaseURL
	apiBaseURL = server.URL + "/"
	defer func() { apiBaseURL = orig }()

	p, _ := New()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := p.Run(ctx, "example.com", "host", nil)
	if err == nil {
		t.Fatal("want error on ctx cancellation")
	}
}

func TestNew_NeverFails(t *testing.T) {
	// L1 适配器不依赖 binary，构造应总成功
	p, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if p == nil || p.client == nil {
		t.Error("Plugin should have client set")
	}
}

func TestKindAndMockFlags(t *testing.T) {
	p := &Plugin{}
	if p.Kind() != "subdomain" {
		t.Errorf("Kind = %q, want subdomain", p.Kind())
	}
	if p.IsMock() {
		t.Errorf("IsMock = true, want false (真插件)")
	}
}
