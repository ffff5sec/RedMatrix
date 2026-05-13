package domain

import (
	"testing"
	"time"
)

func TestComputeHash_Deterministic(t *testing.T) {
	ts := time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC)
	payload := map[string]any{"k": "v", "n": 42}
	h1 := ComputeHash("prev", "t1", ActionLogin, "session", "s1", "u1", "alice", "p1", payload, ts)
	h2 := ComputeHash("prev", "t1", ActionLogin, "session", "s1", "u1", "alice", "p1", payload, ts)
	if h1 != h2 {
		t.Errorf("hash 应确定性，got %s vs %s", h1, h2)
	}
	if len(h1) != 64 {
		t.Errorf("hash 长度应 64 hex，got %d", len(h1))
	}
}

func TestComputeHash_DifferentInputs(t *testing.T) {
	ts := time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC)
	base := ComputeHash("prev", "t1", ActionLogin, "session", "s1", "u1", "a", "p1", nil, ts)

	cases := []struct {
		name string
		got  string
	}{
		{"different prev", ComputeHash("X", "t1", ActionLogin, "session", "s1", "u1", "a", "p1", nil, ts)},
		{"different tenant", ComputeHash("prev", "X", ActionLogin, "session", "s1", "u1", "a", "p1", nil, ts)},
		{"different action", ComputeHash("prev", "t1", ActionLogout, "session", "s1", "u1", "a", "p1", nil, ts)},
		{"different actor", ComputeHash("prev", "t1", ActionLogin, "session", "s1", "X", "a", "p1", nil, ts)},
		{"different payload", ComputeHash("prev", "t1", ActionLogin, "session", "s1", "u1", "a", "p1", map[string]any{"x": 1}, ts)},
		{"different ts", ComputeHash("prev", "t1", ActionLogin, "session", "s1", "u1", "a", "p1", nil, ts.Add(time.Second))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.got == base {
				t.Errorf("应不同；base=%s got=%s", base, c.got)
			}
		})
	}
}

func TestComputeForLog_FillsHash(t *testing.T) {
	pid := "p1"
	uid := "u1"
	a := &AuditLog{
		TenantID:      "t1",
		Action:        ActionLogin,
		ResourceKind:  "session",
		ResourceID:    "s1",
		ActorUserID:   &uid,
		ActorUsername: "alice",
		ProjectID:     &pid,
		Payload:       map[string]any{"x": 1},
		CreatedAt:     time.Now(),
	}
	ComputeForLog(a, GenesisPrevHash)
	if a.PrevHash != GenesisPrevHash {
		t.Errorf("PrevHash should be set to GenesisPrevHash")
	}
	if len(a.Hash) != 64 {
		t.Errorf("Hash 应 64 hex，got %d", len(a.Hash))
	}
}

func TestVerifyChainSegment_Good(t *testing.T) {
	ts := time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC)
	prev := GenesisPrevHash
	rows := []*AuditLog{}
	for i := 0; i < 5; i++ {
		r := &AuditLog{
			TenantID: "t1", Action: ActionLogin, ResourceKind: "session",
			Payload: map[string]any{"i": i}, CreatedAt: ts.Add(time.Duration(i) * time.Second),
		}
		ComputeForLog(r, prev)
		prev = r.Hash
		rows = append(rows, r)
	}
	ok, breakAt := VerifyChainSegment(rows)
	if !ok {
		t.Errorf("good chain 应通过；break at %d", breakAt)
	}
}

func TestVerifyChainSegment_BadHash(t *testing.T) {
	ts := time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC)
	prev := GenesisPrevHash
	rows := []*AuditLog{}
	for i := 0; i < 5; i++ {
		r := &AuditLog{
			TenantID: "t1", Action: ActionLogin, ResourceKind: "session",
			Payload: map[string]any{"i": i}, CreatedAt: ts.Add(time.Duration(i) * time.Second),
		}
		ComputeForLog(r, prev)
		prev = r.Hash
		rows = append(rows, r)
	}
	// 篡改第 3 行的 payload（但 hash 不变）→ 重算应不一致
	rows[2].Payload = map[string]any{"i": 999}
	ok, breakAt := VerifyChainSegment(rows)
	if ok {
		t.Error("篡改后应失败")
	}
	if breakAt != 2 {
		t.Errorf("break_at 应为 2，got %d", breakAt)
	}
}

func TestVerifyChainSegment_BadPrev(t *testing.T) {
	ts := time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC)
	prev := GenesisPrevHash
	rows := []*AuditLog{}
	for i := 0; i < 3; i++ {
		r := &AuditLog{
			TenantID: "t1", Action: ActionLogin, ResourceKind: "session",
			CreatedAt: ts.Add(time.Duration(i) * time.Second),
		}
		ComputeForLog(r, prev)
		prev = r.Hash
		rows = append(rows, r)
	}
	// 改第 2 行的 PrevHash 但不重算 hash
	rows[1].PrevHash = "1111111111111111111111111111111111111111111111111111111111111111"
	ok, _ := VerifyChainSegment(rows)
	if ok {
		t.Error("PrevHash 错应失败")
	}
}

func TestValidateForCreate(t *testing.T) {
	pid := "p1"
	good := &AuditLog{
		TenantID:     "t1",
		Action:       ActionLogin,
		ResourceKind: "session",
		PrevHash:     GenesisPrevHash,
		Hash:         "a" + GenesisPrevHash[1:], // 64 hex char
		ProjectID:    &pid,
	}
	if err := good.ValidateForCreate(); err != nil {
		t.Errorf("good 应通过: %v", err)
	}

	bad := []*AuditLog{
		{TenantID: "", Action: ActionLogin, ResourceKind: "s", PrevHash: GenesisPrevHash, Hash: GenesisPrevHash},
		{TenantID: "t", Action: "bogus", ResourceKind: "s", PrevHash: GenesisPrevHash, Hash: GenesisPrevHash},
		{TenantID: "t", Action: ActionLogin, ResourceKind: "", PrevHash: GenesisPrevHash, Hash: GenesisPrevHash},
		{TenantID: "t", Action: ActionLogin, ResourceKind: "s", PrevHash: "tooShort", Hash: GenesisPrevHash},
		{TenantID: "t", Action: ActionLogin, ResourceKind: "s", PrevHash: GenesisPrevHash, Hash: "tooShort"},
	}
	for i, b := range bad {
		if err := b.ValidateForCreate(); err == nil {
			t.Errorf("bad[%d] 应失败", i)
		}
	}
}
