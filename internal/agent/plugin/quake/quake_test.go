package quake

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

const fixtureOK = `{
  "code": 0,
  "message": "Successful.",
  "data": [
    {"hostname":"sub.example.com","ip":"1.2.3.4","port":443,"org":"Example LLC"},
    {"hostname":"api.example.com","ip":"5.6.7.8","port":8080},
    {"hostname":"","ip":"9.10.11.12","port":25},
    {"hostname":"SUB.Example.COM","ip":"1.2.3.4","port":443}
  ],
  "meta": {"total": 4}
}`

const fixtureError = `{"code":"u3008","message":"quota 用尽 / 配额耗尽","data":null}`

func TestParseResponse_Happy(t *testing.T) {
	rows, err := ParseResponse([]byte(fixtureOK))
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	// sub / api = 2；hostname 空一行跳过；末行 "SUB.Example.COM" 归一与首行重去重
	if len(rows) != 2 {
		t.Fatalf("want 2 rows (dedup + skip-empty-hostname + lowercase), got %d: %+v", len(rows), rows)
	}
	if rows[0]["name"] != "sub.example.com" {
		t.Errorf("rows[0].name = %v", rows[0]["name"])
	}
	if rows[0]["ip"] != "1.2.3.4" {
		t.Errorf("rows[0].ip = %v", rows[0]["ip"])
	}
	if rows[0]["port"] != float64(443) && rows[0]["port"] != 443 {
		t.Errorf("rows[0].port = %v want 443", rows[0]["port"])
	}
	if rows[0]["org"] != "Example LLC" {
		t.Errorf("rows[0].org = %v", rows[0]["org"])
	}
	if rows[0]["source"] != "quake" {
		t.Errorf("rows[0].source = %v", rows[0]["source"])
	}
	if rows[1]["name"] != "api.example.com" {
		t.Errorf("rows[1].name = %v", rows[1]["name"])
	}
}

// Quake "code" 字段类型异常（字符串而非 int）→ ParseResponse 返 json decode 错。
// 这是 MVP 取舍：现实中 v3 接口都是 int code，遇 string 应快速失败而非静默 fallback。
func TestParseResponse_StringCodeFailsDecodingByDesign(t *testing.T) {
	_, err := ParseResponse([]byte(fixtureError))
	if err == nil {
		t.Fatal("want error when code is string (MVP: type-strict decode)")
	}
}

// 用真实的 code=非0 但 int 类型测错误响应路径
func TestParseResponse_NonZeroCode(t *testing.T) {
	in := `{"code":3008,"message":"quota exceeded","data":null}`
	_, err := ParseResponse([]byte(in))
	if err == nil {
		t.Fatal("want error on code != 0")
	}
	if !strings.Contains(err.Error(), "quota exceeded") {
		t.Errorf("err missing message: %v", err)
	}
}

func TestParseResponse_BadJSON(t *testing.T) {
	_, err := ParseResponse([]byte("not-json"))
	if err == nil {
		t.Fatal("want error on bad JSON")
	}
}

func TestParseResponse_EmptyData(t *testing.T) {
	in := `{"code":0,"message":"ok","data":[]}`
	rows, _ := ParseResponse([]byte(in))
	if len(rows) != 0 {
		t.Errorf("want 0, got %d", len(rows))
	}
}

func TestParseResponse_RespectsMax(t *testing.T) {
	orig := MaxSubdomains
	MaxSubdomains = 2
	defer func() { MaxSubdomains = orig }()
	in := `{"code":0,"data":[
{"hostname":"a.example.com"},{"hostname":"b.example.com"},
{"hostname":"c.example.com"},{"hostname":"d.example.com"}]}`
	rows, _ := ParseResponse([]byte(in))
	if len(rows) != 2 {
		t.Errorf("want 2 (max), got %d", len(rows))
	}
}

func TestParseResponse_RejectsIPHostname(t *testing.T) {
	in := `{"code":0,"data":[{"hostname":"192.0.2.1","ip":"192.0.2.1"},{"hostname":"good.example.com"}]}`
	rows, _ := ParseResponse([]byte(in))
	if len(rows) != 1 {
		t.Errorf("want 1 (skip IP hostname), got %d", len(rows))
	}
}

// === HTTP path ===

func TestRun_EndToEnd(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %v want POST", r.Method)
		}
		if r.Header.Get("X-QuakeToken") != "fake-quake-key" {
			t.Errorf("token = %v", r.Header.Get("X-QuakeToken"))
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type = %v", r.Header.Get("Content-Type"))
		}
		// 解 body 校 query
		var body quakeRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode body: %v", err)
		}
		if body.Query != `domain: "example.com"` {
			t.Errorf("body.query = %q", body.Query)
		}
		if body.Size != 100 {
			t.Errorf("body.size = %v want 100", body.Size)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, fixtureOK)
	}))
	defer server.Close()

	orig := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = orig }()

	p := &Plugin{apiKey: "fake-quake-key", client: server.Client()}
	rows, err := p.Run(context.Background(), "example.com", "host", nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(rows) != 2 {
		t.Errorf("want 2 (e2e), got %d", len(rows))
	}
}

func TestRun_NonOKStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, "invalid token")
	}))
	defer server.Close()

	orig := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = orig }()

	p := &Plugin{apiKey: "x", client: server.Client()}
	_, err := p.Run(context.Background(), "example.com", "host", nil)
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("want 401 error, got %v", err)
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
	orig := os.Getenv("QUAKE_KEY")
	_ = os.Unsetenv("QUAKE_KEY")
	defer func() { _ = os.Setenv("QUAKE_KEY", orig) }()
	_, err := New()
	if err == nil {
		t.Fatal("want ErrNotInstalled when env missing")
	}
}

func TestNew_EnvSet(t *testing.T) {
	orig := os.Getenv("QUAKE_KEY")
	_ = os.Setenv("QUAKE_KEY", "uuid-key")
	defer func() { _ = os.Setenv("QUAKE_KEY", orig) }()
	p, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if p.apiKey != "uuid-key" {
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
