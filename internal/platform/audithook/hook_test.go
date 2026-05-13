package audithook

import (
	"context"
	"testing"
)

func TestNoopHook_AlwaysOK(t *testing.T) {
	h := NoopHook{}
	if err := h.Log(context.Background(), Event{}); err != nil {
		t.Errorf("NoopHook.Log 不应失败: %v", err)
	}
}

// 编译期校验 NoopHook 满足 Hook 接口。
var _ Hook = NoopHook{}

func TestEvent_AllFields(t *testing.T) {
	// 仅校字段可填，无 setter；防止 future struct 改动破坏依赖方。
	ev := Event{
		Action:        "login",
		ResourceKind:  "session",
		ResourceID:    "s1",
		TenantID:      "t1",
		ProjectID:     "p1",
		ActorUserID:   "u1",
		ActorUsername: "alice",
		ActorIP:       "10.0.0.1",
		UserAgent:     "curl/8",
		Payload:       map[string]any{"k": "v"},
	}
	if ev.Action != "login" || ev.Payload["k"] != "v" {
		t.Errorf("field assignment 不工作")
	}
}
