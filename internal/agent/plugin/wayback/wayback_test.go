package wayback

import (
	"testing"
)

const fixtureURLs = `https://example.com/login
https://example.com/api/v1/users
https://example.com/admin?id=1

http://example.com/old-page.html
https://example.com/login
not-a-url
ftp://example.com/file.bin
`

func TestParseLines_Happy(t *testing.T) {
	rows, err := ParseLines([]byte(fixtureURLs))
	if err != nil {
		t.Fatalf("ParseLines: %v", err)
	}
	// /login 2 次 dedup → 1；api/users + admin + old-page = 4；ftp 和 "not-a-url" 跳过
	if len(rows) != 4 {
		t.Fatalf("want 4 rows (dedup + filter), got %d: %+v", len(rows), rows)
	}
	if rows[0]["url"] != "https://example.com/login" {
		t.Errorf("rows[0].url = %v", rows[0]["url"])
	}
	if rows[0]["source"] != "wayback" {
		t.Errorf("rows[0].source = %v want wayback", rows[0]["source"])
	}
	if rows[3]["url"] != "http://example.com/old-page.html" {
		t.Errorf("rows[3].url = %v want http: old-page", rows[3]["url"])
	}
}

func TestParseLines_RejectsNonHTTP(t *testing.T) {
	in := `ftp://x.test/a
ssh://x.test/b
file:///etc/passwd
http://good.test/x
https://good.test/y
`
	rows, _ := ParseLines([]byte(in))
	if len(rows) != 2 {
		t.Errorf("want 2 (only http/https), got %d: %+v", len(rows), rows)
	}
}

func TestParseLines_RejectsBadURL(t *testing.T) {
	in := `https://
https://good.test/x
https:// not a real url
http:///nohost.test
`
	rows, _ := ParseLines([]byte(in))
	// 仅 https://good.test/x 合法（缺 host / 非法 URL 都跳过）
	if len(rows) != 1 {
		t.Fatalf("want 1 (skip bad), got %d: %+v", len(rows), rows)
	}
	if rows[0]["url"] != "https://good.test/x" {
		t.Errorf("rows[0].url = %v", rows[0]["url"])
	}
}

func TestParseLines_DedupSameURL(t *testing.T) {
	in := `https://a.test/1
https://a.test/1
https://a.test/2
`
	rows, _ := ParseLines([]byte(in))
	if len(rows) != 2 {
		t.Errorf("want 2 (dedup), got %d", len(rows))
	}
}

func TestParseLines_RespectsMaxResults(t *testing.T) {
	orig := MaxResults
	MaxResults = 2
	defer func() { MaxResults = orig }()
	in := `https://a.test/1
https://a.test/2
https://a.test/3
https://a.test/4
`
	rows, _ := ParseLines([]byte(in))
	if len(rows) != 2 {
		t.Errorf("want 2 (max), got %d", len(rows))
	}
}

func TestParseLines_Empty(t *testing.T) {
	rows, err := ParseLines([]byte(""))
	if err != nil {
		t.Fatalf("empty: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("want 0, got %d", len(rows))
	}
}

func TestNew_NotInstalled_Stub(t *testing.T) {
	orig := binaryName
	binaryName = "waybackurls-not-exist-zz"
	defer func() { binaryName = orig }()
	if _, err := New(); err == nil {
		t.Error("expected ErrNotInstalled")
	}
}

func TestKindAndMockFlags(t *testing.T) {
	p := &Plugin{}
	if p.Kind() != "web_crawl" {
		t.Errorf("Kind = %q, want web_crawl", p.Kind())
	}
	if p.IsMock() {
		t.Errorf("IsMock = true, want false (真插件)")
	}
}
