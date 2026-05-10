package subfinder

import (
	"testing"
)

const fixtureNDJSON = `{"host":"api.example.com","input":"example.com","source":"alienvault"}
{"host":"www.example.com","input":"example.com","source":"crtsh"}

{"host":"mail.example.com","input":"example.com","source":"securitytrails"}
`

func TestParseJSONLines_Happy(t *testing.T) {
	rows, err := ParseJSONLines([]byte(fixtureNDJSON))
	if err != nil {
		t.Fatalf("ParseJSONLines: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("want 3 rows, got %d", len(rows))
	}
	if rows[0]["name"] != "api.example.com" || rows[0]["source"] != "alienvault" {
		t.Errorf("rows[0]: %+v", rows[0])
	}
	if rows[1]["name"] != "www.example.com" {
		t.Errorf("rows[1]: %+v", rows[1])
	}
	if rows[2]["name"] != "mail.example.com" {
		t.Errorf("rows[2]: %+v", rows[2])
	}
}

func TestParseJSONLines_BadLineSkipped(t *testing.T) {
	in := `{"host":"good.example.com","source":"crtsh"}
this-is-not-json
{"host":"also-good.example.com"}
`
	rows, err := ParseJSONLines([]byte(in))
	if err != nil {
		t.Fatalf("ParseJSONLines: %v", err)
	}
	if len(rows) != 2 {
		t.Errorf("want 2 (skip bad), got %d", len(rows))
	}
}

func TestParseJSONLines_Empty(t *testing.T) {
	rows, err := ParseJSONLines([]byte(""))
	if err != nil {
		t.Fatalf("ParseJSONLines empty: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("want 0, got %d", len(rows))
	}
}

func TestParseJSONLines_HostNormalized(t *testing.T) {
	in := `{"host":"  API.Example.COM  ","source":"x"}
`
	rows, err := ParseJSONLines([]byte(in))
	if err != nil || len(rows) != 1 {
		t.Fatalf("parse: rows=%d err=%v", len(rows), err)
	}
	if rows[0]["name"] != "api.example.com" {
		t.Errorf("name not normalized: %v", rows[0]["name"])
	}
}

func TestNew_NotInstalled_Stub(t *testing.T) {
	orig := binaryName
	binaryName = "subfinder-this-does-not-exist-zz"
	defer func() { binaryName = orig }()
	if _, err := New(); err == nil {
		t.Error("expected ErrNotInstalled")
	}
}
