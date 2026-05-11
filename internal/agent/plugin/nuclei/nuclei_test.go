package nuclei

import (
	"testing"
)

const fixtureNDJSON = `{"template-id":"CVE-2023-12345","info":{"name":"Foo SQL Injection","severity":"high","description":"..."},"host":"https://example.com","matched-at":"https://example.com/api/sql","type":"http"}
{"template-id":"tech-detect/nginx","info":{"name":"Nginx detected","severity":"info"},"host":"https://example.com","matched-at":"https://example.com","type":"http"}

{"this":"is-not-a-valid-nuclei-entry"}
{"template-id":"CVE-2024-99999","info":{"name":"Test critical","severity":"critical","description":"Boom"},"host":"https://example.com","matched-at":"https://example.com/foo","type":"http"}
`

func TestParseJSONLines_Happy(t *testing.T) {
	rows, err := ParseJSONLines([]byte(fixtureNDJSON))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// fixture：4 行 valid JSON 中 3 行有 template-id（含 1 行无 template-id 应 skip）
	if len(rows) != 3 {
		t.Fatalf("want 3, got %d", len(rows))
	}
	if rows[0]["template_id"] != "CVE-2023-12345" {
		t.Errorf("rows[0].template_id: %v", rows[0]["template_id"])
	}
	if rows[0]["severity"] != "high" {
		t.Errorf("rows[0].severity: %v", rows[0]["severity"])
	}
	if rows[0]["name"] != "Foo SQL Injection" {
		t.Errorf("rows[0].name: %v", rows[0]["name"])
	}
	if rows[1]["template_id"] != "tech-detect/nginx" {
		t.Errorf("rows[1].template_id: %v", rows[1]["template_id"])
	}
	if rows[2]["severity"] != "critical" {
		t.Errorf("rows[2].severity: %v", rows[2]["severity"])
	}
}

func TestParseJSONLines_Empty(t *testing.T) {
	rows, err := ParseJSONLines([]byte(""))
	if err != nil {
		t.Fatalf("parse empty: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("want 0, got %d", len(rows))
	}
}

func TestParseJSONLines_BadLineSkipped(t *testing.T) {
	in := `not-json
{"template-id":"good","info":{"severity":"low"}}
again-not-json
`
	rows, err := ParseJSONLines([]byte(in))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(rows) != 1 {
		t.Errorf("want 1 (skip bad), got %d", len(rows))
	}
}

func TestParseJSONLines_SeverityLowercased(t *testing.T) {
	in := `{"template-id":"x","info":{"severity":"HIGH"}}
`
	rows, err := ParseJSONLines([]byte(in))
	if err != nil || len(rows) != 1 {
		t.Fatalf("parse: %d %v", len(rows), err)
	}
	if rows[0]["severity"] != "high" {
		t.Errorf("severity not lowercased: %v", rows[0]["severity"])
	}
}

func TestParseJSONLines_MaxResultsCap(t *testing.T) {
	// 拼 600 行
	var buf []byte
	for i := 0; i < 600; i++ {
		buf = append(buf, []byte(`{"template-id":"t-x","info":{"severity":"low"}}`+"\n")...)
	}
	rows, err := ParseJSONLines(buf)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(rows) != MaxResults {
		t.Errorf("want cap to %d, got %d", MaxResults, len(rows))
	}
}

func TestValidSeverityList(t *testing.T) {
	good := []string{
		"high", "high,critical", "low,medium,high,critical",
		"info", "unknown",
	}
	for _, g := range good {
		if !validSeverityList(g) {
			t.Errorf("%q should be valid", g)
		}
	}
	bad := []string{
		"",                  // empty
		"all",               // not in set
		"-h",                // arg injection
		"high;rm -rf /",     // shell meta
		"high,bogus",        // mixed bad
		"high,,critical",    // empty list element
	}
	for _, b := range bad {
		if validSeverityList(b) {
			t.Errorf("%q should be invalid", b)
		}
	}
}

func TestNew_NotInstalled(t *testing.T) {
	orig := binaryName
	binaryName = "nuclei-this-does-not-exist-zz"
	defer func() { binaryName = orig }()
	if _, err := New(); err == nil {
		t.Error("expected ErrNotInstalled")
	}
}
