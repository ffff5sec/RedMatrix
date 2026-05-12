package domain

import "testing"

func TestExtractSubdomainHosts(t *testing.T) {
	got := ExtractTargetsForKind(KindSubdomain, []ResultData{
		{"host": "a.example.com"},
		{"host": "b.example.com"},
		{"host": "  a.example.com  "}, // dup
		{"host": ""},                  // empty
		{},                            // missing host
	})
	want := []string{"a.example.com", "b.example.com"}
	if !equalSlice(got, want) {
		t.Errorf("want %v, got %v", want, got)
	}
}

func TestExtractFingerprintURLs_LiveOnly(t *testing.T) {
	got := ExtractTargetsForKind(KindFingerprint, []ResultData{
		{"url": "https://a.test/", "status_code": float64(200)},
		{"url": "http://b.test/", "status_code": 301},          // 3xx 算 live
		{"url": "https://c.test/", "status_code": 404},         // 4xx 跳过
		{"url": "https://d.test/", "status_code": 500},         // 5xx 跳过
		{"url": "https://a.test/path?q=1", "status_code": 200}, // dedup（去 path）
		{"host": "no-scheme.test", "status_code": 200},         // 没 url 取 host
	})
	want := []string{"https://a.test", "http://b.test", "no-scheme.test"}
	if !equalSlice(got, want) {
		t.Errorf("want %v, got %v", want, got)
	}
}

func TestExtractTargetsForKind_TerminalKinds(t *testing.T) {
	cases := []TaskKind{KindVulnScan, KindWebCrawl, KindPortScan}
	for _, k := range cases {
		got := ExtractTargetsForKind(k, []ResultData{{"host": "x"}})
		if got != nil {
			t.Errorf("kind=%s should be terminal (nil), got %v", k, got)
		}
	}
}

func TestNormalizeURLForChaining(t *testing.T) {
	cases := []struct {
		in, out string
	}{
		{"https://a.test/", "https://a.test"},
		{"https://a.test/some/path", "https://a.test"},
		{"https://a.test:8443/?q=1", "https://a.test:8443"},
		{"no-scheme.test", "no-scheme.test"},
		{"", ""},
	}
	for _, c := range cases {
		got := normalizeURLForChaining(c.in)
		if got != c.out {
			t.Errorf("in=%q want %q got %q", c.in, c.out, got)
		}
	}
}

// equalSlice 在 target_expand_test.go 已定义；本文件复用。
