package ksubdomain

import (
	"testing"
)

const fixturePlain = `api.example.com
www.example.com

mail.example.com
API.Example.COM
`

func TestParseLines_Happy(t *testing.T) {
	rows, err := ParseLines([]byte(fixturePlain))
	if err != nil {
		t.Fatalf("ParseLines: %v", err)
	}
	// api / www / mail = 3；末行 "API.Example.COM" 归一为 api.example.com 与首行重，去重
	if len(rows) != 3 {
		t.Fatalf("want 3 rows (dedup + lowercase), got %d: %+v", len(rows), rows)
	}
	if rows[0]["name"] != "api.example.com" {
		t.Errorf("rows[0].name = %v", rows[0]["name"])
	}
	if rows[0]["source"] != "ksubdomain" {
		t.Errorf("rows[0].source = %v want ksubdomain", rows[0]["source"])
	}
	if rows[2]["name"] != "mail.example.com" {
		t.Errorf("rows[2].name = %v", rows[2]["name"])
	}
}

// TestParseLines_RejectsBannerLines —— ksubdomain 输出残留 banner / "[+]" 标记 /
// IP 地址 / 端口号 / 控制字符 都不应作为 host 入 row。
func TestParseLines_RejectsBannerLines(t *testing.T) {
	in := `[+] ksubdomain v1.10.0
[*] starting scan...
192.0.2.1
:53
not a valid domain
sub.example.com
good.example.com
`
	rows, _ := ParseLines([]byte(in))
	// 仅 sub.example.com + good.example.com 合法
	if len(rows) != 2 {
		t.Fatalf("want 2 (skip banner / IP), got %d: %+v", len(rows), rows)
	}
	if rows[0]["name"] != "sub.example.com" || rows[1]["name"] != "good.example.com" {
		t.Errorf("rows = %+v", rows)
	}
}

func TestParseLines_HostLowercased(t *testing.T) {
	in := `WWW.Example.COM
`
	rows, _ := ParseLines([]byte(in))
	if len(rows) != 1 {
		t.Fatalf("want 1, got %d", len(rows))
	}
	if rows[0]["name"] != "www.example.com" {
		t.Errorf("name not lowercased: %v", rows[0]["name"])
	}
}

func TestParseLines_DedupSameName(t *testing.T) {
	in := `a.example.com
a.example.com
b.example.com
`
	rows, _ := ParseLines([]byte(in))
	if len(rows) != 2 {
		t.Errorf("want 2 (dedup), got %d", len(rows))
	}
}

func TestParseLines_RespectsMaxSubdomains(t *testing.T) {
	orig := MaxSubdomains
	MaxSubdomains = 2
	defer func() { MaxSubdomains = orig }()
	in := `a.example.com
b.example.com
c.example.com
d.example.com
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

// TestReadPositiveInt 验证 settings 数字字段从 float64 / int 取值。
func TestReadPositiveInt(t *testing.T) {
	cases := []struct {
		name string
		val  any
		want int
		ok   bool
	}{
		{"float64", float64(100), 100, true},
		{"int", 50, 50, true},
		{"negative", float64(-1), 0, false},
		{"zero", 0, 0, false},
		{"missing", nil, 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := map[string]any{"k": c.val}
			got, ok := readPositiveInt(s, "k")
			if got != c.want || ok != c.ok {
				t.Errorf("got=(%d,%v) want=(%d,%v)", got, ok, c.want, c.ok)
			}
		})
	}
}

func TestNew_NotInstalled_Stub(t *testing.T) {
	orig := binaryName
	binaryName = "ksubdomain-not-exist-zz"
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
