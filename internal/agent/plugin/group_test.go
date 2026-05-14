package plugin

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// stubPlugin 测试用的可控 Plugin。
type stubPlugin struct {
	kind   string
	mock   bool
	rows   []map[string]any
	err    error
	called int // 调用计数（验证串行调用）
}

func (s *stubPlugin) Kind() string { return s.kind }
func (s *stubPlugin) IsMock() bool { return s.mock }
func (s *stubPlugin) Run(_ context.Context, _, _ string, _ map[string]any) ([]map[string]any, error) {
	s.called++
	return s.rows, s.err
}

func TestGroup_KindFromFirst(t *testing.T) {
	g := newGroup([]Plugin{&stubPlugin{kind: "subdomain"}, &stubPlugin{kind: "subdomain"}})
	if g.Kind() != "subdomain" {
		t.Errorf("Kind = %q, want subdomain", g.Kind())
	}
}

func TestGroup_IsMockAggregation(t *testing.T) {
	allMock := newGroup([]Plugin{&stubPlugin{mock: true}, &stubPlugin{mock: true}})
	if !allMock.IsMock() {
		t.Error("全 mock 应返 true")
	}
	mixed := newGroup([]Plugin{&stubPlugin{mock: true}, &stubPlugin{mock: false}})
	if mixed.IsMock() {
		t.Error("含 1 真插件应返 false")
	}
	allReal := newGroup([]Plugin{&stubPlugin{mock: false}, &stubPlugin{mock: false}})
	if allReal.IsMock() {
		t.Error("全真应返 false")
	}
}

func TestGroup_Run_AllSucceed_MergesResults(t *testing.T) {
	a := &stubPlugin{kind: "subdomain", rows: []map[string]any{{"name": "a.example.com"}}}
	b := &stubPlugin{kind: "subdomain", rows: []map[string]any{{"name": "b.example.com"}, {"name": "c.example.com"}}}
	g := newGroup([]Plugin{a, b})

	rows, err := g.Run(context.Background(), "example.com", "host", nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("want 3 (1+2 merged), got %d: %+v", len(rows), rows)
	}
	if a.called != 1 || b.called != 1 {
		t.Errorf("called counts: a=%d b=%d (both should be 1)", a.called, b.called)
	}
}

func TestGroup_Run_PartialFail_ReturnsSuccessfulResults(t *testing.T) {
	a := &stubPlugin{kind: "subdomain", rows: []map[string]any{{"name": "a.test"}}}
	b := &stubPlugin{kind: "subdomain", err: errors.New("b is down")}
	c := &stubPlugin{kind: "subdomain", rows: []map[string]any{{"name": "c.test"}}}
	g := newGroup([]Plugin{a, b, c})

	rows, err := g.Run(context.Background(), "x", "host", nil)
	if err != nil {
		t.Fatalf("部分失败应返 nil error (拿到部分结果)，但得到: %v", err)
	}
	if len(rows) != 2 {
		t.Errorf("want 2 (skip failed b), got %d", len(rows))
	}
	if b.called != 1 || c.called != 1 {
		t.Errorf("b/c 都应被调用即使 b 失败")
	}
}

func TestGroup_Run_AllFail_ReturnsCompoundError(t *testing.T) {
	a := &stubPlugin{kind: "subdomain", err: errors.New("a down")}
	b := &stubPlugin{kind: "subdomain", err: errors.New("b timeout")}
	g := newGroup([]Plugin{a, b})

	_, err := g.Run(context.Background(), "x", "host", nil)
	if err == nil {
		t.Fatal("全失败应返复合 error")
	}
	if !strings.Contains(err.Error(), "all 2 sub-plugins failed") {
		t.Errorf("error message missing summary: %v", err)
	}
	if !strings.Contains(err.Error(), "a down") || !strings.Contains(err.Error(), "b timeout") {
		t.Errorf("error 应含两个子错: %v", err)
	}
}

func TestGroup_Run_SinglePlugin_DirectPassThrough(t *testing.T) {
	rows := []map[string]any{{"name": "only.test"}}
	one := &stubPlugin{kind: "subdomain", rows: rows}
	g := newGroup([]Plugin{one})

	got, err := g.Run(context.Background(), "x", "host", nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(got) != 1 || got[0]["name"] != "only.test" {
		t.Errorf("single plugin pass-through failed: %+v", got)
	}
}

func TestGroup_Run_EmptyGroup_ReturnsError(t *testing.T) {
	g := newGroup(nil)
	_, err := g.Run(context.Background(), "x", "host", nil)
	if err == nil {
		t.Fatal("empty group 应返 error")
	}
}

func TestGroup_NilPointer_Safe(t *testing.T) {
	var g *group
	if g.Kind() != "" {
		t.Error("nil group Kind 应返空")
	}
	if !g.IsMock() {
		t.Error("nil group IsMock 应返 true (保守)")
	}
	if _, err := g.Run(context.Background(), "x", "host", nil); err == nil {
		t.Error("nil group Run 应返 error")
	}
}

func TestAsGroup(t *testing.T) {
	g := newGroup([]Plugin{&stubPlugin{}})
	if asGroup(g) != g {
		t.Error("asGroup 应返同实例")
	}
	non := &stubPlugin{}
	if asGroup(non) != nil {
		t.Error("非 group 应返 nil")
	}
}
