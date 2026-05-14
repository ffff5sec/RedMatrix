package fingerprintx

import (
	"strings"
	"testing"
)

const fixtureJSON = `{"host":"example.com","ip":"93.184.216.34","port":443,"protocol":"https","tls":true,"transport":"tcp","version":""}
{"host":"example.com","ip":"93.184.216.34","port":22,"protocol":"ssh","tls":false,"transport":"tcp","version":"OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"}

{"ip":"10.0.0.5","port":6379,"protocol":"redis","tls":false,"transport":"tcp"}
`

func TestParseJSONLines_Happy(t *testing.T) {
	rows, err := ParseJSONLines([]byte(fixtureJSON))
	if err != nil {
		t.Fatalf("ParseJSONLines: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("want 3 rows, got %d: %+v", len(rows), rows)
	}
	// rows[0]: example.com:443 https tls
	if rows[0]["host"] != "example.com" {
		t.Errorf("rows[0].host = %v", rows[0]["host"])
	}
	if rows[0]["target"] != "example.com" {
		t.Errorf("rows[0].target = %v want example.com (alias)", rows[0]["target"])
	}
	if rows[0]["port"] != 443 {
		t.Errorf("rows[0].port = %v want 443", rows[0]["port"])
	}
	if rows[0]["protocol"] != "https" {
		t.Errorf("rows[0].protocol = %v", rows[0]["protocol"])
	}
	if rows[0]["tls"] != true {
		t.Errorf("rows[0].tls = %v want true", rows[0]["tls"])
	}
	// rows[1]: ssh banner version
	if rows[1]["protocol"] != "ssh" {
		t.Errorf("rows[1].protocol = %v", rows[1]["protocol"])
	}
	if !strings.HasPrefix(rows[1]["version"].(string), "OpenSSH") {
		t.Errorf("rows[1].version = %v", rows[1]["version"])
	}
	// rows[2]: 缺 host，用 ip 作 target
	if rows[2]["target"] != "10.0.0.5" {
		t.Errorf("rows[2].target = %v want fall back to ip", rows[2]["target"])
	}
	if _, has := rows[2]["host"]; has {
		t.Errorf("rows[2] should not have host key when host empty")
	}
	// tls=false 不应出现在 row（节省 payload）
	if _, has := rows[2]["tls"]; has {
		t.Errorf("rows[2].tls=false should be omitted, got %v", rows[2]["tls"])
	}
}

func TestParseJSONLines_BadLineSkipped(t *testing.T) {
	in := `{"host":"good.test","ip":"1.2.3.4","port":80,"protocol":"http"}
this-is-not-json
{"host":"also.test","ip":"1.2.3.5","port":443,"protocol":"https","tls":true}
`
	rows, err := ParseJSONLines([]byte(in))
	if err != nil {
		t.Fatalf("ParseJSONLines: %v", err)
	}
	if len(rows) != 2 {
		t.Errorf("want 2 (skip bad), got %d", len(rows))
	}
}

func TestParseJSONLines_EmptyHostAndIP_Skipped(t *testing.T) {
	in := `{"port":80,"protocol":"http"}
{"host":"good.test","ip":"1.2.3.4","port":80,"protocol":"http"}
`
	rows, _ := ParseJSONLines([]byte(in))
	if len(rows) != 1 {
		t.Errorf("want 1 (skip empty host+ip), got %d", len(rows))
	}
}

func TestParseJSONLines_HostLowercased(t *testing.T) {
	in := `{"host":"WWW.Example.COM","ip":"1.2.3.4","port":80,"protocol":"http"}
`
	rows, _ := ParseJSONLines([]byte(in))
	if len(rows) != 1 {
		t.Fatalf("want 1, got %d", len(rows))
	}
	if rows[0]["host"] != "www.example.com" {
		t.Errorf("host not lowercased: %v", rows[0]["host"])
	}
}

func TestParseJSONLines_ProtocolLowercased(t *testing.T) {
	in := `{"host":"a.test","ip":"1.2.3.4","port":80,"protocol":"HTTP"}
`
	rows, _ := ParseJSONLines([]byte(in))
	if len(rows) != 1 {
		t.Fatalf("want 1, got %d", len(rows))
	}
	if rows[0]["protocol"] != "http" {
		t.Errorf("protocol not lowercased: %v", rows[0]["protocol"])
	}
}

func TestParseJSONLines_RespectsMaxResults(t *testing.T) {
	orig := MaxResults
	MaxResults = 2
	defer func() { MaxResults = orig }()
	in := `{"host":"a.test","ip":"1.0.0.1","port":80,"protocol":"http"}
{"host":"b.test","ip":"1.0.0.2","port":80,"protocol":"http"}
{"host":"c.test","ip":"1.0.0.3","port":80,"protocol":"http"}
{"host":"d.test","ip":"1.0.0.4","port":80,"protocol":"http"}
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

// === target 拆分 / 端口扩展 ===

func TestSplitHostPort(t *testing.T) {
	cases := []struct {
		in       string
		wantHost string
		wantPort string
	}{
		{"example.com", "example.com", ""},
		{"example.com:443", "example.com", "443"},
		{"1.2.3.4", "1.2.3.4", ""},
		{"1.2.3.4:8080", "1.2.3.4", "8080"},
		{"https://example.com/foo", "https://example.com/foo", ""}, // URL 不拆
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			h, p := splitHostPort(c.in)
			if h != c.wantHost || p != c.wantPort {
				t.Errorf("got (%q,%q) want (%q,%q)", h, p, c.wantHost, c.wantPort)
			}
		})
	}
}

func TestExpandHostPorts(t *testing.T) {
	cases := []struct {
		host  string
		ports string
		want  string
	}{
		{"example.com", "80,443", "example.com:80,example.com:443"},
		{"a.test", "80,443,8080", "a.test:80,a.test:443,a.test:8080"},
		{"a.test", "22-24", "a.test:22,a.test:23,a.test:24"},
		{"a.test", "21,22-23", "a.test:21,a.test:22,a.test:23"},
		// 不合法段跳过
		{"a.test", "80,abc,443", "a.test:80,a.test:443"},
		{"a.test", "70000,443", "a.test:443"}, // 超 65535 跳过
	}
	for _, c := range cases {
		t.Run(c.ports, func(t *testing.T) {
			got := expandHostPorts(c.host, c.ports)
			if got != c.want {
				t.Errorf("got %q want %q", got, c.want)
			}
		})
	}
}

func TestNew_NotInstalled_Stub(t *testing.T) {
	orig := binaryName
	binaryName = "fingerprintx-not-exist-zz"
	defer func() { binaryName = orig }()
	if _, err := New(); err == nil {
		t.Error("expected ErrNotInstalled")
	}
}

func TestKindAndMockFlags(t *testing.T) {
	p := &Plugin{}
	if p.Kind() != "fingerprint" {
		t.Errorf("Kind = %q, want fingerprint", p.Kind())
	}
	if p.IsMock() {
		t.Errorf("IsMock = true, want false (真插件)")
	}
}
