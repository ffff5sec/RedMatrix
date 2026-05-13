package tlsx

import (
	"testing"
)

const fixtureNDJSON = `{"host":"example.com","port":"443","subject_cn":"*.example.com","issuer_cn":"Sectigo RSA Domain Validation Secure Server CA","not_before":"2024-11-01T00:00:00Z","not_after":"2025-12-02T23:59:59Z","fingerprint_hash":{"sha256":"abcd1234"},"subject_an":["*.example.com","example.com"],"tls_version":"tls13"}
{"host":"api.example.com","port":"443","subject_cn":"api.example.com","issuer_cn":"Let's Encrypt R3","not_before":"2024-10-01T00:00:00Z","not_after":"2024-12-30T00:00:00Z","fingerprint_hash":{"sha256":"ef567890"},"tls_version":"tls12"}

{"host":"self.example.test","port":"8443","subject_cn":"self.example.test","issuer_cn":"self.example.test","not_after":"2025-01-01T00:00:00Z","fingerprint_hash":{"sha256":"deadbeef"},"self_signed":true,"wildcard_cert":false}
`

func TestParseJSONLines_Happy(t *testing.T) {
	rows, err := ParseJSONLines([]byte(fixtureNDJSON))
	if err != nil {
		t.Fatalf("ParseJSONLines: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("want 3 rows, got %d", len(rows))
	}
	if rows[0]["host"] != "example.com" {
		t.Errorf("rows[0].host = %v", rows[0]["host"])
	}
	if rows[0]["port"] != "443" {
		t.Errorf("rows[0].port = %v", rows[0]["port"])
	}
	if rows[0]["subject_cn"] != "*.example.com" {
		t.Errorf("rows[0].subject_cn = %v", rows[0]["subject_cn"])
	}
	if rows[0]["not_after"] != "2025-12-02T23:59:59Z" {
		t.Errorf("rows[0].not_after = %v", rows[0]["not_after"])
	}
	if rows[0]["sha256"] != "abcd1234" {
		t.Errorf("rows[0].sha256 = %v", rows[0]["sha256"])
	}
	sans, ok := rows[0]["sans"].([]string)
	if !ok || len(sans) != 2 || sans[0] != "*.example.com" {
		t.Errorf("rows[0].sans = %v", rows[0]["sans"])
	}
	if rows[0]["tls_version"] != "tls13" {
		t.Errorf("rows[0].tls_version = %v", rows[0]["tls_version"])
	}
}

// TestParseJSONLines_SelfSignedFlagged 验证 self-signed 标记被解析到 row。
func TestParseJSONLines_SelfSignedFlagged(t *testing.T) {
	rows, _ := ParseJSONLines([]byte(fixtureNDJSON))
	if len(rows) < 3 {
		t.Fatalf("want 3 rows")
	}
	if rows[2]["self_signed"] != true {
		t.Errorf("rows[2].self_signed = %v want true", rows[2]["self_signed"])
	}
	// wildcard_cert=false 不应出现在 row 里（节省 payload）
	if _, has := rows[2]["wildcard"]; has {
		t.Errorf("rows[2] should not have wildcard=false key")
	}
}

// TestParseJSONLines_HostNormalized host 大小写归一为小写。
func TestParseJSONLines_HostNormalized(t *testing.T) {
	in := `{"host":"API.Example.COM","port":"443"}
`
	rows, _ := ParseJSONLines([]byte(in))
	if len(rows) != 1 {
		t.Fatalf("want 1, got %d", len(rows))
	}
	if rows[0]["host"] != "api.example.com" {
		t.Errorf("host not lowercased: %v", rows[0]["host"])
	}
}

// TestParseJSONLines_BadLineSkipped 单行 JSON 错跳过，整体不毁。
func TestParseJSONLines_BadLineSkipped(t *testing.T) {
	in := `{"host":"good.example.com","port":"443"}
this-is-not-json
{"host":"also-good.example.com","port":"443"}
`
	rows, err := ParseJSONLines([]byte(in))
	if err != nil {
		t.Fatalf("ParseJSONLines: %v", err)
	}
	if len(rows) != 2 {
		t.Errorf("want 2 (skip bad), got %d", len(rows))
	}
}

// TestParseJSONLines_EmptyHostSkipped host 为空的行不入 row。
func TestParseJSONLines_EmptyHostSkipped(t *testing.T) {
	in := `{"host":"","port":"443","subject_cn":"x"}
{"host":"good.example.com","port":"443"}
`
	rows, _ := ParseJSONLines([]byte(in))
	if len(rows) != 1 {
		t.Errorf("want 1 (skip empty host), got %d", len(rows))
	}
}

func TestParseJSONLines_Empty(t *testing.T) {
	rows, err := ParseJSONLines([]byte(""))
	if err != nil {
		t.Fatalf("empty: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("want 0, got %d", len(rows))
	}
}

// TestParseJSONLines_RespectsMaxResults 超过 MaxResults 后截断。
func TestParseJSONLines_RespectsMaxResults(t *testing.T) {
	orig := MaxResults
	MaxResults = 2
	defer func() { MaxResults = orig }()
	in := `{"host":"a.example.com","port":"443"}
{"host":"b.example.com","port":"443"}
{"host":"c.example.com","port":"443"}
{"host":"d.example.com","port":"443"}
`
	rows, _ := ParseJSONLines([]byte(in))
	if len(rows) != 2 {
		t.Errorf("want 2 (max), got %d", len(rows))
	}
}

func TestNew_NotInstalled_Stub(t *testing.T) {
	orig := binaryName
	binaryName = "tlsx-this-does-not-exist-zz"
	defer func() { binaryName = orig }()
	if _, err := New(); err == nil {
		t.Error("expected ErrNotInstalled")
	}
}

// TestKindAndMockFlags 编译期断言 Plugin 接口约定。
func TestKindAndMockFlags(t *testing.T) {
	p := &Plugin{}
	if p.Kind() != "tls_scan" {
		t.Errorf("Kind = %q, want tls_scan", p.Kind())
	}
	if p.IsMock() {
		t.Errorf("IsMock = true, want false (真插件)")
	}
}
