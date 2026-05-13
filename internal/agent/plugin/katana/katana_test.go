package katana

import (
	"testing"
)

// fixture：扁平 + 嵌套两种 katana 输出形态都包含
const fixtureNDJSON = `{"endpoint":"https://example.com/a","method":"GET","tag":"link","status_code":200}
{"endpoint":"https://example.com/b","method":"GET","tag":"form"}

{"timestamp":"2026-05-14T00:00:00Z","request":{"endpoint":"https://example.com/c","method":"POST"}}
{"endpoint":"https://example.com/a","method":"GET","tag":"link"}
`

func TestParseJSONLines_Happy(t *testing.T) {
	rows, err := ParseJSONLines([]byte(fixtureNDJSON))
	if err != nil {
		t.Fatalf("ParseJSONLines: %v", err)
	}
	// /a 出现两次但去重后 1 条；/b /c 各 1 条 → 共 3
	if len(rows) != 3 {
		t.Fatalf("want 3 rows (deduped), got %d: %+v", len(rows), rows)
	}
	if rows[0]["url"] != "https://example.com/a" {
		t.Errorf("rows[0].url = %v", rows[0]["url"])
	}
	if rows[0]["status_code"] != 200 {
		t.Errorf("rows[0].status_code = %v want 200", rows[0]["status_code"])
	}
	if rows[2]["url"] != "https://example.com/c" {
		t.Errorf("rows[2].url = %v want /c", rows[2]["url"])
	}
	if rows[2]["method"] != "POST" {
		t.Errorf("rows[2].method = %v want POST (from nested request)", rows[2]["method"])
	}
}

func TestParseJSONLines_NestedRequestFallback(t *testing.T) {
	in := `{"request":{"endpoint":"https://example.com/api","method":"GET"}}
`
	rows, _ := ParseJSONLines([]byte(in))
	if len(rows) != 1 {
		t.Fatalf("want 1, got %d", len(rows))
	}
	if rows[0]["url"] != "https://example.com/api" {
		t.Errorf("url = %v", rows[0]["url"])
	}
}

func TestParseJSONLines_BadLineSkipped(t *testing.T) {
	in := `{"endpoint":"https://good.test/x"}
this-is-not-json
{"endpoint":"https://good.test/y"}
`
	rows, err := ParseJSONLines([]byte(in))
	if err != nil {
		t.Fatalf("ParseJSONLines: %v", err)
	}
	if len(rows) != 2 {
		t.Errorf("want 2 (skip bad), got %d", len(rows))
	}
}

func TestParseJSONLines_EmptyEndpointSkipped(t *testing.T) {
	in := `{"endpoint":""}
{"endpoint":"https://good.test/x"}
`
	rows, _ := ParseJSONLines([]byte(in))
	if len(rows) != 1 {
		t.Errorf("want 1 (skip empty endpoint), got %d", len(rows))
	}
}

func TestParseJSONLines_RespectsMaxResults(t *testing.T) {
	orig := MaxResults
	MaxResults = 2
	defer func() { MaxResults = orig }()
	in := `{"endpoint":"https://a.test/1"}
{"endpoint":"https://a.test/2"}
{"endpoint":"https://a.test/3"}
{"endpoint":"https://a.test/4"}
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

// TestReadPositiveInt 验证 settings 数字字段从 float64 / int / json.Number 取值。
func TestReadPositiveInt(t *testing.T) {
	cases := []struct {
		name string
		val  any
		want int
		ok   bool
	}{
		{"float64", float64(3), 3, true},
		{"int", 5, 5, true},
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

func TestClampInt(t *testing.T) {
	if clampInt(10, 1, 5) != 5 {
		t.Errorf("clamp high failed")
	}
	if clampInt(0, 1, 5) != 1 {
		t.Errorf("clamp low failed")
	}
	if clampInt(3, 1, 5) != 3 {
		t.Errorf("in range failed")
	}
}

func TestNew_NotInstalled_Stub(t *testing.T) {
	orig := binaryName
	binaryName = "katana-not-exist-zz"
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
