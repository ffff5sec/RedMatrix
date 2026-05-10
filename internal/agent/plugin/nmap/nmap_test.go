package nmap

import (
	"testing"
)

const fixtureXML = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sT -p 22,80,443 127.0.0.1" start="1747000000" version="7.94">
<host starttime="1747000000" endtime="1747000005">
<status state="up" reason="user-set"/>
<address addr="127.0.0.1" addrtype="ipv4"/>
<hostnames>
<hostname name="localhost" type="user"/>
</hostnames>
<ports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="OpenSSH" version="9.6" extrainfo="protocol 2.0"/></port>
<port protocol="tcp" portid="80"><state state="closed" reason="conn-refused"/><service name="http"/></port>
<port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/><service name="https" product="nginx" version="1.24.0"/></port>
</ports>
</host>
</nmaprun>`

func TestParseXML_OpenPortsOnly(t *testing.T) {
	rows, err := ParseXML([]byte(fixtureXML))
	if err != nil {
		t.Fatalf("ParseXML: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("want 2 open ports (22, 443), got %d", len(rows))
	}
	// 第 1 条 22/ssh
	if rows[0]["host"] != "127.0.0.1" {
		t.Errorf("rows[0].host: %v", rows[0]["host"])
	}
	if rows[0]["port"] != 22 {
		t.Errorf("rows[0].port: %v", rows[0]["port"])
	}
	if rows[0]["service"] != "ssh" {
		t.Errorf("rows[0].service: %v", rows[0]["service"])
	}
	if banner, _ := rows[0]["banner"].(string); banner == "" {
		t.Errorf("rows[0].banner empty; want OpenSSH 9.6 (protocol 2.0)")
	}
	// 第 2 条 443/https/nginx
	if rows[1]["port"] != 443 {
		t.Errorf("rows[1].port: %v", rows[1]["port"])
	}
	if banner, _ := rows[1]["banner"].(string); banner == "" {
		t.Errorf("rows[1].banner empty")
	}
}

func TestParseXML_NoHosts(t *testing.T) {
	const empty = `<?xml version="1.0"?><nmaprun></nmaprun>`
	rows, err := ParseXML([]byte(empty))
	if err != nil {
		t.Fatalf("ParseXML: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("expected 0, got %d", len(rows))
	}
}

func TestParseXML_BadXML(t *testing.T) {
	if _, err := ParseXML([]byte("<<not xml")); err == nil {
		t.Error("expected error on malformed xml")
	}
}

func TestNew_NotInstalled_Stub(t *testing.T) {
	// 临时把 binaryName 改成几乎肯定不存在的名字
	orig := binaryName
	binaryName = "nmap-this-does-not-exist-on-any-system-zz"
	defer func() { binaryName = orig }()
	if _, err := New(); err == nil {
		t.Error("expected ErrNotInstalled when binary missing")
	}
}
