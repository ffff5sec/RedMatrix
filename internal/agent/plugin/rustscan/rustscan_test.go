package rustscan

import (
	"testing"
)

// fixture：rustscan 2.x 主流 greppable 形态
const fixtureGreppable2x = `192.0.2.1 -> [22,80,443]
192.0.2.2 -> [22]
192.0.2.3 -> []
`

// fixture：rustscan 1.x 老形态
const fixtureLegacy1x = `Starting rustscan v1.10.0
Open 10.0.0.1:22
Open 10.0.0.1:80
Open 10.0.0.2:443
`

func TestParseGreppable_2x_Happy(t *testing.T) {
	rows, err := ParseGreppable([]byte(fixtureGreppable2x))
	if err != nil {
		t.Fatalf("ParseGreppable: %v", err)
	}
	// 192.0.2.1 3 端口 + 192.0.2.2 1 端口 + 192.0.2.3 0 端口 = 4
	if len(rows) != 4 {
		t.Fatalf("want 4 rows, got %d: %+v", len(rows), rows)
	}
	if rows[0]["host"] != "192.0.2.1" || rows[0]["port"] != 22 {
		t.Errorf("rows[0] = %+v", rows[0])
	}
	if rows[2]["port"] != 443 {
		t.Errorf("rows[2].port = %v want 443", rows[2]["port"])
	}
	if rows[3]["host"] != "192.0.2.2" {
		t.Errorf("rows[3].host = %v want 192.0.2.2", rows[3]["host"])
	}
}

func TestParseGreppable_1x_LegacyHappy(t *testing.T) {
	rows, err := ParseGreppable([]byte(fixtureLegacy1x))
	if err != nil {
		t.Fatalf("ParseGreppable: %v", err)
	}
	// 跳过 "Starting..." banner，3 行 Open
	if len(rows) != 3 {
		t.Fatalf("want 3 rows, got %d: %+v", len(rows), rows)
	}
	if rows[0]["host"] != "10.0.0.1" || rows[0]["port"] != 22 {
		t.Errorf("rows[0] = %+v", rows[0])
	}
}

// TestParseGreppable_InvalidPortSkipped 端口字段非数字 / 超 65535 → 跳过。
func TestParseGreppable_InvalidPortSkipped(t *testing.T) {
	in := `192.0.2.1 -> [22,abc,99999,-1,80]
`
	rows, _ := ParseGreppable([]byte(in))
	// 仅 22 + 80 合法
	if len(rows) != 2 {
		t.Fatalf("want 2 (skip invalid ports), got %d: %+v", len(rows), rows)
	}
	if rows[0]["port"] != 22 || rows[1]["port"] != 80 {
		t.Errorf("ports = %v %v", rows[0]["port"], rows[1]["port"])
	}
}

func TestParseGreppable_EmptyBracket(t *testing.T) {
	in := `192.0.2.1 -> []
`
	rows, _ := ParseGreppable([]byte(in))
	if len(rows) != 0 {
		t.Errorf("want 0 (host with no open ports), got %d", len(rows))
	}
}

func TestParseGreppable_BannerSkipped(t *testing.T) {
	in := `[~] Starting rustscan v2.3
[~] Scanning 192.0.2.1
192.0.2.1 -> [22]
[~] Done in 0.5s
`
	rows, _ := ParseGreppable([]byte(in))
	if len(rows) != 1 {
		t.Errorf("want 1 (skip banner), got %d", len(rows))
	}
}

func TestParseGreppable_RespectsMaxResults(t *testing.T) {
	orig := MaxResults
	MaxResults = 2
	defer func() { MaxResults = orig }()
	in := `192.0.2.1 -> [22,80,443,8443,9090]
`
	rows, _ := ParseGreppable([]byte(in))
	if len(rows) != 2 {
		t.Errorf("want 2 (max), got %d", len(rows))
	}
}

func TestParseGreppable_Empty(t *testing.T) {
	rows, err := ParseGreppable([]byte(""))
	if err != nil {
		t.Fatalf("empty: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("want 0, got %d", len(rows))
	}
}

func TestNew_NotInstalled_Stub(t *testing.T) {
	orig := binaryName
	binaryName = "rustscan-not-exist-zz"
	defer func() { binaryName = orig }()
	if _, err := New(); err == nil {
		t.Error("expected ErrNotInstalled")
	}
}

func TestKindAndMockFlags(t *testing.T) {
	p := &Plugin{}
	if p.Kind() != "port_scan" {
		t.Errorf("Kind = %q, want port_scan", p.Kind())
	}
	if p.IsMock() {
		t.Errorf("IsMock = true, want false (真插件)")
	}
}
