package domain

import (
	"strings"
	"testing"
)

func TestExpandTargets_PassThrough(t *testing.T) {
	got, err := ExpandTargets([]string{"example.com", "1.2.3.4", "https://x.test/api"}, 100)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	want := []string{"example.com", "1.2.3.4", "https://x.test/api"}
	if !equalSlice(got, want) {
		t.Errorf("want %v, got %v", want, got)
	}
}

func TestExpandTargets_CIDR_v4_24(t *testing.T) {
	got, err := ExpandTargets([]string{"192.168.1.0/24"}, 300)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(got) != 256 {
		t.Fatalf("want 256, got %d", len(got))
	}
	if got[0] != "192.168.1.0" || got[255] != "192.168.1.255" {
		t.Errorf("boundary wrong: first=%s last=%s", got[0], got[255])
	}
}

func TestExpandTargets_CIDR_v4_30(t *testing.T) {
	got, err := ExpandTargets([]string{"10.0.0.0/30"}, 100)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	want := []string{"10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3"}
	if !equalSlice(got, want) {
		t.Errorf("want %v, got %v", want, got)
	}
}

func TestExpandTargets_Range_Full(t *testing.T) {
	got, err := ExpandTargets([]string{"192.168.1.10-192.168.1.13"}, 100)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	want := []string{"192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.13"}
	if !equalSlice(got, want) {
		t.Errorf("want %v, got %v", want, got)
	}
}

func TestExpandTargets_Range_Short(t *testing.T) {
	got, err := ExpandTargets([]string{"192.168.1.10-13"}, 100)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	want := []string{"192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.13"}
	if !equalSlice(got, want) {
		t.Errorf("want %v, got %v", want, got)
	}
}

func TestExpandTargets_HostnameWithHyphen_NotARange(t *testing.T) {
	got, err := ExpandTargets([]string{"my-server.example.com"}, 100)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	want := []string{"my-server.example.com"}
	if !equalSlice(got, want) {
		t.Errorf("hostname with hyphen should pass through, got %v", got)
	}
}

func TestExpandTargets_Mixed(t *testing.T) {
	got, err := ExpandTargets([]string{
		"example.com",
		"10.0.0.0/30",
		"192.168.1.10-12",
	}, 100)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	want := []string{
		"example.com",
		"10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3",
		"192.168.1.10", "192.168.1.11", "192.168.1.12",
	}
	if !equalSlice(got, want) {
		t.Errorf("want %v, got %v", want, got)
	}
}

func TestExpandTargets_Dedup(t *testing.T) {
	got, err := ExpandTargets([]string{
		"192.168.1.10",
		"192.168.1.10-12",
		"192.168.1.11",
	}, 100)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	want := []string{"192.168.1.10", "192.168.1.11", "192.168.1.12"}
	if !equalSlice(got, want) {
		t.Errorf("want %v, got %v", want, got)
	}
}

func TestExpandTargets_TrimAndEmpty(t *testing.T) {
	got, err := ExpandTargets([]string{"  example.com  ", "", "  "}, 100)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	want := []string{"example.com"}
	if !equalSlice(got, want) {
		t.Errorf("want %v, got %v", want, got)
	}
}

func TestExpandTargets_OverLimit(t *testing.T) {
	_, err := ExpandTargets([]string{"10.0.0.0/24"}, 100)
	if err == nil {
		t.Fatal("expected over-limit error")
	}
	if !strings.Contains(err.Error(), "超过上限") {
		t.Errorf("want over-limit msg, got %v", err)
	}
}

func TestExpandTargets_InvalidCIDR(t *testing.T) {
	_, err := ExpandTargets([]string{"not-a-cidr/24"}, 100)
	if err == nil {
		t.Fatal("expected CIDR error")
	}
}

func TestExpandTargets_RangeReverse(t *testing.T) {
	_, err := ExpandTargets([]string{"192.168.1.20-10"}, 100)
	if err == nil {
		t.Fatal("expected reverse-range error")
	}
}

func TestExpandTargets_URL_NotCIDR(t *testing.T) {
	got, err := ExpandTargets([]string{"https://x.test/path/sub"}, 100)
	if err != nil {
		t.Fatalf("URL with '/' should pass through, got err %v", err)
	}
	want := []string{"https://x.test/path/sub"}
	if !equalSlice(got, want) {
		t.Errorf("want %v, got %v", want, got)
	}
}

func TestExpandTargets_IPv6CIDR_TooLoose(t *testing.T) {
	_, err := ExpandTargets([]string{"2001:db8::/64"}, 100)
	if err == nil {
		t.Fatal("expected IPv6 prefix-too-small error")
	}
	if !strings.Contains(err.Error(), "IPv6") {
		t.Errorf("want IPv6 msg, got %v", err)
	}
}

func TestExpandTargets_IPv6CIDR_OK(t *testing.T) {
	// /126 = 4 个地址
	got, err := ExpandTargets([]string{"2001:db8::/126"}, 100)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(got) != 4 {
		t.Errorf("want 4, got %d (%v)", len(got), got)
	}
}

func TestPreviewExpandTargets_Truncated(t *testing.T) {
	got, total, truncated, err := PreviewExpandTargets([]string{"10.0.0.0/24"}, 100)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if total != 256 {
		t.Errorf("want total=256, got %d", total)
	}
	if !truncated {
		t.Error("want truncated=true")
	}
	if len(got) != 100 {
		t.Errorf("want len=100, got %d", len(got))
	}
}

func TestPreviewExpandTargets_NotTruncated(t *testing.T) {
	got, total, truncated, err := PreviewExpandTargets([]string{"10.0.0.0/30", "host.com"}, 100)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if total != 5 {
		t.Errorf("want total=5, got %d", total)
	}
	if truncated {
		t.Error("want truncated=false")
	}
	if len(got) != 5 {
		t.Errorf("want len=5, got %d", len(got))
	}
}

func equalSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
