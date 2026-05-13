package amass

import (
	"testing"
)

const fixtureNDJSON = `{"name":"api.example.com","domain":"example.com","sources":["crtsh","alienvault"]}
{"name":"www.example.com","domain":"example.com","sources":["dnsdumpster"]}

{"name":"mail.example.com","domain":"example.com"}
{"name":"  API.Example.COM  ","domain":"example.com","sources":["dup-source"]}
`

func TestParseJSONLines_Happy(t *testing.T) {
	rows, err := ParseJSONLines([]byte(fixtureNDJSON))
	if err != nil {
		t.Fatalf("ParseJSONLines: %v", err)
	}
	// api / www / mail = 3；末行 "API.Example.COM" 归一为 "api.example.com" 与首行重，去重
	if len(rows) != 3 {
		t.Fatalf("want 3 rows (after dedup + lowercase), got %d: %+v", len(rows), rows)
	}
	if rows[0]["name"] != "api.example.com" {
		t.Errorf("rows[0].name = %v", rows[0]["name"])
	}
	if rows[0]["source"] != "crtsh" {
		t.Errorf("rows[0].source = %v want crtsh (first of sources[])", rows[0]["source"])
	}
	// mail 行无 sources 字段 → 不应有 source key
	if _, has := rows[2]["source"]; has {
		t.Errorf("rows[2] should not have source key (sources empty)")
	}
}

func TestParseJSONLines_HostLowercased(t *testing.T) {
	in := `{"name":"WWW.Example.COM","sources":["x"]}
`
	rows, _ := ParseJSONLines([]byte(in))
	if len(rows) != 1 {
		t.Fatalf("want 1, got %d", len(rows))
	}
	if rows[0]["name"] != "www.example.com" {
		t.Errorf("name not lowercased: %v", rows[0]["name"])
	}
}

func TestParseJSONLines_DedupSameName(t *testing.T) {
	in := `{"name":"a.example.com","sources":["s1"]}
{"name":"a.example.com","sources":["s2"]}
{"name":"b.example.com","sources":["s3"]}
`
	rows, _ := ParseJSONLines([]byte(in))
	if len(rows) != 2 {
		t.Errorf("want 2 (dedup), got %d", len(rows))
	}
}

func TestParseJSONLines_BadLineSkipped(t *testing.T) {
	in := `{"name":"good.example.com"}
this-is-not-json
{"name":"also-good.example.com"}
`
	rows, err := ParseJSONLines([]byte(in))
	if err != nil {
		t.Fatalf("ParseJSONLines: %v", err)
	}
	if len(rows) != 2 {
		t.Errorf("want 2 (skip bad), got %d", len(rows))
	}
}

func TestParseJSONLines_EmptyNameSkipped(t *testing.T) {
	in := `{"name":""}
{"name":"   "}
{"name":"good.example.com"}
`
	rows, _ := ParseJSONLines([]byte(in))
	if len(rows) != 1 {
		t.Errorf("want 1 (skip empty), got %d", len(rows))
	}
}

func TestParseJSONLines_RespectsMaxSubdomains(t *testing.T) {
	orig := MaxSubdomains
	MaxSubdomains = 2
	defer func() { MaxSubdomains = orig }()
	in := `{"name":"a.example.com"}
{"name":"b.example.com"}
{"name":"c.example.com"}
{"name":"d.example.com"}
`
	rows, _ := ParseJSONLines([]byte(in))
	if len(rows) != 2 {
		t.Errorf("want 2 (max), got %d", len(rows))
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

func TestNew_NotInstalled_Stub(t *testing.T) {
	orig := binaryName
	binaryName = "amass-not-exist-zz"
	defer func() { binaryName = orig }()
	if _, err := New(); err == nil {
		t.Error("expected ErrNotInstalled")
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
