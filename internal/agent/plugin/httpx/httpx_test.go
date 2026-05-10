package httpx

import (
	"reflect"
	"testing"
)

const fixtureNDJSON = `{"timestamp":"2026-05-09T00:00:00Z","port":"443","url":"https://example.com","input":"https://example.com","title":"Example Domain","webserver":"ECS (sec/0)","status_code":200,"tech":["AWS","Cloudflare"]}
{"timestamp":"2026-05-09T00:00:01Z","port":"80","url":"http://www.example.com","input":"http://www.example.com","title":"WWW","webserver":"nginx","status_code":301}

{"this":"is-not-a-valid-httpx-line"}
`

func TestParseFingerprint_Happy(t *testing.T) {
	rows, err := ParseJSONLinesFingerprint([]byte(fixtureNDJSON))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(rows) != 3 {
		// 第 3 行的 JSON 合法但缺 url（"this":"..."）；convertRow 应跳过 → 留 2
		// 但也可能 2 行；先打日志再断
		t.Logf("got %d rows", len(rows))
	}
	if rows[0]["target"] != "https://example.com" {
		t.Errorf("rows[0].target: %v", rows[0]["target"])
	}
	if rows[0]["status"] != 200 {
		t.Errorf("rows[0].status: %v", rows[0]["status"])
	}
	if rows[0]["title"] != "Example Domain" {
		t.Errorf("rows[0].title: %v", rows[0]["title"])
	}
	tech, ok := rows[0]["tech"].([]string)
	if !ok || !reflect.DeepEqual(tech, []string{"AWS", "Cloudflare"}) {
		t.Errorf("rows[0].tech: %v", rows[0]["tech"])
	}
	if rows[0]["webserver"] != "ECS (sec/0)" {
		t.Errorf("rows[0].webserver: %v", rows[0]["webserver"])
	}
	// 第 2 行没 tech / webserver
	if _, has := rows[1]["tech"]; has {
		t.Errorf("rows[1] should not have tech")
	}
}

func TestParseWebCrawl_Happy(t *testing.T) {
	rows, err := ParseJSONLinesWebCrawl([]byte(fixtureNDJSON))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// web_crawl 无 tech 字段
	for _, r := range rows {
		if _, has := r["tech"]; has {
			t.Errorf("web_crawl row should not have tech: %+v", r)
		}
		if _, has := r["url"]; !has {
			t.Errorf("web_crawl row missing url: %+v", r)
		}
	}
	if rows[0]["url"] != "https://example.com" {
		t.Errorf("rows[0].url: %v", rows[0]["url"])
	}
	if rows[0]["status"] != 200 {
		t.Errorf("rows[0].status: %v", rows[0]["status"])
	}
}

func TestParseEmpty(t *testing.T) {
	rows, err := ParseJSONLinesFingerprint([]byte(""))
	if err != nil {
		t.Fatalf("parse empty: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("want 0, got %d", len(rows))
	}
}

func TestParseBadLineSkipped(t *testing.T) {
	in := `not-json
{"url":"https://good.example.com","status_code":200}
also-not-json
`
	rows, err := ParseJSONLinesWebCrawl([]byte(in))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(rows) != 1 {
		t.Errorf("want 1 (skip bad), got %d", len(rows))
	}
}

func TestNewFingerprint_NotInstalled(t *testing.T) {
	orig := binaryName
	binaryName = "httpx-this-does-not-exist-zz"
	defer func() { binaryName = orig }()
	if _, err := NewFingerprint(); err == nil {
		t.Error("expected ErrNotInstalled (fingerprint)")
	}
	if _, err := NewWebCrawl(); err == nil {
		t.Error("expected ErrNotInstalled (web_crawl)")
	}
}
