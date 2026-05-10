package scheduler

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// stubListing 让测试控 LoadAll 输入。
type stubListing struct {
	rows []CronTemplate
	err  error
}

func (s *stubListing) ListCronTemplates(_ context.Context) ([]CronTemplate, error) {
	return s.rows, s.err
}

func TestAddRemove_Idempotent(t *testing.T) {
	s, err := New(&stubListing{}, func(context.Context, string) {}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.Add("task-1", "*/1 * * * *"); err != nil {
		t.Fatalf("Add 1: %v", err)
	}
	if s.Count() != 1 {
		t.Errorf("count after add: %d", s.Count())
	}
	// 重复 Add 不应增加（覆盖语义）
	if err := s.Add("task-1", "*/2 * * * *"); err != nil {
		t.Fatalf("Add 1 again: %v", err)
	}
	if s.Count() != 1 {
		t.Errorf("count after re-add: %d", s.Count())
	}
	// Remove
	s.Remove("task-1")
	if s.Count() != 0 {
		t.Errorf("count after remove: %d", s.Count())
	}
	// Remove 不存在的 → no-op
	s.Remove("task-1")
	s.Remove("task-zz")
}

func TestAdd_RejectsBadCron(t *testing.T) {
	s, _ := New(&stubListing{}, func(context.Context, string) {}, nil)
	if err := s.Add("t-bad", "not a cron"); err == nil {
		t.Error("expected error on bad cron")
	}
}

func TestLoadAll_LoadsAll(t *testing.T) {
	listing := &stubListing{rows: []CronTemplate{
		{TaskID: "t1", CronExpr: "*/1 * * * *"},
		{TaskID: "t2", CronExpr: "0 * * * *"},
	}}
	s, _ := New(listing, func(context.Context, string) {}, nil)
	if err := s.LoadAll(context.Background()); err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if s.Count() != 2 {
		t.Errorf("loaded count: %d", s.Count())
	}
}

func TestLoadAll_SkipsBadEntries(t *testing.T) {
	listing := &stubListing{rows: []CronTemplate{
		{TaskID: "t-good", CronExpr: "*/1 * * * *"},
		{TaskID: "t-bad", CronExpr: "garbage"},
	}}
	s, _ := New(listing, func(context.Context, string) {}, nil)
	if err := s.LoadAll(context.Background()); err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if s.Count() != 1 {
		t.Errorf("expect 1 (skip bad), got %d", s.Count())
	}
}

// TestTrigger_FiresCallback：用每秒 cron 验证回调被调用至少一次。
// robfig/cron 标准 5 字段无秒，最快粒度 1 分钟；这里要测 trigger 命中
// 必须改用 cron.WithSeconds() —— 但我们 prod 不开秒级。
//
// 折中：直接调内部 makeJob 验证回调路径正常；不依赖 cron 真火。
func TestTrigger_CallbackPath(t *testing.T) {
	var got atomic.Int32
	wg := sync.WaitGroup{}
	wg.Add(1)
	s, _ := New(&stubListing{}, func(_ context.Context, taskID string) {
		if taskID == "t-fire" {
			got.Add(1)
		}
		wg.Done()
	}, nil)
	job := s.makeJob("t-fire")
	go job()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("trigger never fired")
	}
	if got.Load() != 1 {
		t.Errorf("got: %d", got.Load())
	}
}

func TestNew_NilArgs(t *testing.T) {
	if _, err := New(nil, func(context.Context, string) {}, nil); err == nil {
		t.Error("expected err on nil listing")
	}
	if _, err := New(&stubListing{}, nil, nil); err == nil {
		t.Error("expected err on nil trigger")
	}
}
