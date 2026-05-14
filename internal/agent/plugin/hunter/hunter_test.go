package hunter

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
  "code": 200,
  "message": "success",
  "data": {
    "total": 4,
    "arr": [
      {"url":"https://sub.example.com","ip":"1.2.3.4","port":443,"domain":"sub.example.com","status_code":200},
      {"url":"http://api.example.com:8080","ip":"5.6.7.8","port":8080,"domain":"api.example.com","status_code":403},
      {"url":"https://mail.example.com","ip":"9.10.11.12","port":443,"domain":"","status_code":200},
      {"url":"https://API.Example.COM","ip":"1.2.3.4","port":443,"domain":"API.Example.COM","status_code":200}
    ]
  }
}`

const fixtureError = `{"code":401,"message":"unauthorized: invalid api-key","data":null}`

func TestParseResponse_Happy(t *testing.T) {
	rows, err := ParseResponse([]byte(fixtureOK))
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	// sub / api / mail = 3；末行 "API.Example.COM" 归一为 sub.example.com 与首行重去重
	if len(rows) != 3 {
		t.Fatalf("want 3 rows (dedup + lowercase + url-fallback), got %d: %+v", len(rows), rows)
	}
	if rows[0]["name"] != "sub.example.com" {
		t.Errorf("rows[0].name = %v", rows[0]["name"])
	}
	if rows[0]["ip"] != "1.2.3.4" {
		t.Errorf("rows[0].ip = %v", rows[0]["ip"])
	}
	if rows[0]["port"] != 443 {
		t.Errorf("rows[0].port = %v want 443 (int)", rows[0]["port"])
	}
	if rows[0]["status_code"] != 200 {
		t.Errorf("rows[0].status_code = %v", rows[0]["status_code"])
	}
	if rows[0]["source"] != "hunter" {
		t.Errorf("rows[0].source = %v", rows[0]["source"])
	}
	// rows[2]: domain 字段为空 → 从 url 字段 fallback 出 mail.example.com
	if rows[2]["name"] != "mail.example.com" {
		t.Errorf("rows[2].name = %v want mail.example.com (url fallback)", rows[2]["name"])
	}
}

func TestParseResponse_ErrorResponse(t *testing.T) {
	_, err := ParseResponse([]byte(fixtureError))
	if err == nil {
		t.Fatal("want error on code != 200")
	}
	if !strings.Contains(err.Error(), "unauthorized") {
		t.Errorf("err missing message: %v", err)
	}
}

func TestParseResponse_BadJSON(t *testing.T) {
	_, err := ParseResponse([]byte("not-json"))
	if err == nil {
		t.Fatal("want error on bad JSON")
	}
}

func TestParseResponse_EmptyArr(t *testing.T) {
	in := `{"code":200,"data":{"total":0,"arr":[]}}`
	rows, _ := ParseResponse([]byte(in))
	if len(rows) != 0 {
		t.Errorf("want 0, got %d", len(rows))
	}
}

func TestParseResponse_RespectsMax(t *testing.T) {
	orig := MaxSubdomains
	MaxSubdomains = 2
	defer func() { MaxSubdomains = orig }()
	in := `{"code":200,"data":{"arr":[
{"domain":"a.example.com"},{"domain":"b.example.com"},{"domain":"c.example.com"},{"domain":"d.example.com"}
]}}`
	rows, _ := ParseResponse([]byte(in))
	if len(rows) != 2 {
		t.Errorf("want 2 (max), got %d", len(rows))
	}
}

func TestParseResponse_URLFallbackOnly(t *testing.T) {
	in := `{"code":200,"data":{"arr":[{"url":"https://only-url.example.com/path"}]}}`
	rows, _ := ParseResponse([]byte(in))
	if len(rows) != 1 {
		t.Fatalf("want 1, got %d", len(rows))
	}
	if rows[0]["name"] != "only-url.example.com" {
		t.Errorf("url fallback failed: %v", rows[0]["name"])
	}
}

func TestParseResponse_RejectsIPDomain(t *testing.T) {
	in := `{"code":200,"data":{"arr":[
{"domain":"192.0.2.1","ip":"192.0.2.1"},
{"domain":"good.example.com","ip":"1.2.3.4"}
]}}`
	rows, _ := ParseResponse([]byte(in))
	if len(rows) != 1 {
		t.Errorf("want 1 (skip IP domain), got %d: %+v", len(rows), rows)
	}
}

// === HTTP path ===

func TestRun_EndToEnd(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("api-key") != "fake-key" {
			t.Errorf("api-key = %v", r.URL.Query().Get("api-key"))
		}
		sb := r.URL.Query().Get("search")
		decoded, err := base64.URLEncoding.DecodeString(sb)
		if err != nil {
			t.Errorf("search base64 invalid: %v", err)
		}
		if string(decoded) != `domain="example.com"` {
			t.Errorf("search decoded = %q", string(decoded))
		}
		if r.URL.Query().Get("page_size") != "100" {
			t.Errorf("page_size = %v", r.URL.Query().Get("page_size"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, fixtureOK)
	}))
	defer server.Close()

	orig := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = orig }()

	p := &Plugin{apiKey: "fake-key", client: server.Client()}
	rows, err := p.Run(context.Background(), "example.com", "host", nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(rows) != 3 {
		t.Errorf("want 3 (e2e), got %d", len(rows))
	}
}

func TestRun_NonOKStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	orig := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = orig }()

	p := &Plugin{apiKey: "x", client: server.Client()}
	_, err := p.Run(context.Background(), "example.com", "host", nil)
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("want 403 error, got %v", err)
	}
}

func TestRun_RejectsNonHost(t *testing.T) {
	p := &Plugin{apiKey: "x", client: http.DefaultClient}
	_, err := p.Run(context.Background(), "192.0.2.1", "ip", nil)
	if err == nil {
		t.Fatal("want error on target_kind=ip")
	}
}

func TestNew_MissingEnv(t *testing.T) {
	orig := os.Getenv("HUNTER_KEY")
	_ = os.Unsetenv("HUNTER_KEY")
	defer func() { _ = os.Setenv("HUNTER_KEY", orig) }()

	_, err := New()
	if err == nil {
		t.Fatal("want ErrNotInstalled when env missing")
	}
}

func TestNew_EnvSet(t *testing.T) {
	orig := os.Getenv("HUNTER_KEY")
	_ = os.Setenv("HUNTER_KEY", "abc-123")
	defer func() { _ = os.Setenv("HUNTER_KEY", orig) }()

	p, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if p.apiKey != "abc-123" {
		t.Errorf("apiKey not loaded: %v", p.apiKey)
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
