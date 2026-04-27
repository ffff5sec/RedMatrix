package version

import (
	"strings"
	"testing"
)

func TestStringContainsDefaults(t *testing.T) {
	got := String()
	if !strings.Contains(got, Version) {
		t.Fatalf("String() = %q, want it to contain Version %q", got, Version)
	}
	if !strings.Contains(got, "commit") {
		t.Fatalf("String() = %q, want it to contain %q", got, "commit")
	}
	if !strings.Contains(got, "built") {
		t.Fatalf("String() = %q, want it to contain %q", got, "built")
	}
}

func TestDefaultsAreNotEmpty(t *testing.T) {
	defaults := map[string]string{
		"Version":   Version,
		"Commit":    Commit,
		"BuildDate": BuildDate,
	}
	for name, v := range defaults {
		if v == "" {
			t.Errorf("%s is empty (must default to placeholder)", name)
		}
	}
}
