package domain

import (
	"testing"
	"time"
)

// PR-S31 资产 freshness helper 测试。

func TestAsset_IsStale(t *testing.T) {
	now := time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name      string
		lastSeen  time.Time
		threshold time.Duration
		want      bool
	}{
		{"recent_not_stale", now.Add(-1 * time.Hour), 24 * time.Hour, false},
		{"exactly_threshold_not_stale", now.Add(-24 * time.Hour), 24 * time.Hour, false},
		{"just_past_threshold", now.Add(-25 * time.Hour), 24 * time.Hour, true},
		{"very_old", now.Add(-90 * 24 * time.Hour), 24 * time.Hour, true},
		{"zero_threshold_never_stale", now.Add(-365 * 24 * time.Hour), 0, false},
		{"negative_threshold_never_stale", now, -1 * time.Hour, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := &Asset{LastSeen: c.lastSeen}
			if got := a.IsStale(c.threshold, now); got != c.want {
				t.Errorf("IsStale=%v, want %v (lastSeen=%v threshold=%v)",
					got, c.want, c.lastSeen, c.threshold)
			}
		})
	}
}

func TestAsset_IsStale_NilSafe(t *testing.T) {
	var a *Asset
	if a.IsStale(time.Hour, time.Now()) {
		t.Error("nil asset 不应 stale")
	}
}
