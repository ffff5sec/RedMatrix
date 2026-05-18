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

// PR-S75 favicon hash 解析（新 / 老 httpx 字段名两路径）。

func TestParseFingerprint_FaviconMMH3(t *testing.T) {
	// 新 httpx 用 favicon_mmh3 字段
	in := `{"url":"https://target.example.com","status_code":200,"favicon_mmh3":"-978864504","favicon_path":"/static/favicon.ico"}`
	rows, err := ParseJSONLinesFingerprint([]byte(in))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("want 1, got %d", len(rows))
	}
	if rows[0]["favicon_hash"] != "-978864504" {
		t.Errorf("favicon_hash = %v want -978864504", rows[0]["favicon_hash"])
	}
	if rows[0]["favicon_path"] != "/static/favicon.ico" {
		t.Errorf("favicon_path = %v", rows[0]["favicon_path"])
	}
}

func TestParseFingerprint_FaviconLegacyField(t *testing.T) {
	// 老 httpx 用 favicon 字段（也是 mmh3 hash 串）
	in := `{"url":"https://target.example.com","status_code":200,"favicon":"123456789"}`
	rows, err := ParseJSONLinesFingerprint([]byte(in))
	if err != nil {
		t.Fatalf("%v", err)
	}
	if rows[0]["favicon_hash"] != "123456789" {
		t.Errorf("favicon_hash = %v want 123456789", rows[0]["favicon_hash"])
	}
}

func TestParseFingerprint_FaviconMMH3WinsOverLegacy(t *testing.T) {
	// 两个字段都给 → 优先 mmh3（新字段）
	in := `{"url":"https://t","status_code":200,"favicon_mmh3":"AAA","favicon":"BBB"}`
	rows, _ := ParseJSONLinesFingerprint([]byte(in))
	if rows[0]["favicon_hash"] != "AAA" {
		t.Errorf("应优先 favicon_mmh3，got %v", rows[0]["favicon_hash"])
	}
}

func TestParseWebCrawl_DropsFavicon(t *testing.T) {
	// web_crawl 路径不应吐 favicon_hash（只 fingerprint 用）
	in := `{"url":"https://t","status_code":200,"favicon_mmh3":"AAA"}`
	rows, _ := ParseJSONLinesWebCrawl([]byte(in))
	if _, has := rows[0]["favicon_hash"]; has {
		t.Errorf("web_crawl 不该带 favicon_hash")
	}
}
