package gospider

import (
	"testing"
)

const fixtureJSON = `{"output_type":"href","input":"https://example.com","source":"body","output":"https://example.com/a","status":"200","length":1234}
{"output_type":"form","input":"https://example.com","source":"body","output":"https://example.com/login","status":"200"}

{"output_type":"linkfinder","input":"https://example.com","source":"js","output":"https://example.com/api/v1/users"}
{"output_type":"href","input":"https://example.com","source":"body","output":"https://example.com/a"}
`

func TestParseJSONLines_Happy(t *testing.T) {
	rows, err := ParseJSONLines([]byte(fixtureJSON))
	if err != nil {
		t.Fatalf("ParseJSONLines: %v", err)
	}
	// /a 出现两次去重 → 共 3
	if len(rows) != 3 {
		t.Fatalf("want 3 rows (deduped), got %d: %+v", len(rows), rows)
	}
	if rows[0]["url"] != "https://example.com/a" {
		t.Errorf("rows[0].url = %v", rows[0]["url"])
	}
	if rows[0]["tag"] != "href" {
		t.Errorf("rows[0].tag = %v want href", rows[0]["tag"])
	}
	if rows[0]["source"] != "body" {
		t.Errorf("rows[0].source = %v", rows[0]["source"])
	}
	if rows[0]["status_code"] != "200" {
		t.Errorf("rows[0].status_code = %v", rows[0]["status_code"])
	}
	if rows[0]["length"] != 1234 {
		t.Errorf("rows[0].length = %v", rows[0]["length"])
	}
	if rows[1]["tag"] != "form" {
		t.Errorf("rows[1].tag = %v want form", rows[1]["tag"])
	}
	if rows[2]["tag"] != "linkfinder" {
		t.Errorf("rows[2].tag = %v want linkfinder", rows[2]["tag"])
	}
}

func TestParseJSONLines_EmptyOutputSkipped(t *testing.T) {
	in := `{"output_type":"href","output":""}
{"output_type":"href","output":"https://good.test/x"}
`
	rows, _ := ParseJSONLines([]byte(in))
	if len(rows) != 1 {
		t.Errorf("want 1 (skip empty output), got %d", len(rows))
	}
}

func TestParseJSONLines_BadLineSkipped(t *testing.T) {
	in := `{"output":"https://a.test/1"}
not-json
{"output":"https://a.test/2"}
`
	rows, err := ParseJSONLines([]byte(in))
	if err != nil {
		t.Fatalf("ParseJSONLines: %v", err)
	}
	if len(rows) != 2 {
		t.Errorf("want 2 (skip bad), got %d", len(rows))
	}
}

func TestParseJSONLines_RespectsMaxResults(t *testing.T) {
	orig := MaxResults
	MaxResults = 2
	defer func() { MaxResults = orig }()
	in := `{"output":"https://a.test/1"}
{"output":"https://a.test/2"}
{"output":"https://a.test/3"}
{"output":"https://a.test/4"}
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
		t.Errorf("in-range failed")
	}
}

func TestNew_NotInstalled_Stub(t *testing.T) {
	orig := binaryName
	binaryName = "gospider-not-exist-zz"
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
