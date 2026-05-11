// Package scheduler 是 scan 模块的周期任务调度器（PR-S12）。
//
// 模型：scan_tasks 行 schedule_kind=cron 是"模板"；按 cron_expr 定时触发，
// 触发时复用 service.CreateTask 创建一条 schedule_kind=immediate 的"实例"
// task（name 加时间后缀）；实例的 dispatch 链路与手动创建任务无差别。
//
// 崩溃恢复：MVP 不补偿——重启后 LoadAll 从 PG 重新装载所有 cron task；
// 错过的 trigger 不补跑，从下一次时刻继续。
package scheduler

import (
	"context"
	"sync"

	"github.com/robfig/cron/v3"

	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/platform/log"
	"github.com/ffff5sec/RedMatrix/internal/scan/domain"
)

// TaskListing 返回一份 cron task 模板信息（taskID + cronExpr）；
// 由 caller 实现（一般是 scan repo / service 的薄包装）。
type TaskListing interface {
	// ListCronTemplates 返所有 schedule_kind=cron 且 status 不在终态/canceled 的 task。
	// 实现可加 deleted_at IS NULL 过滤。
	ListCronTemplates(ctx context.Context) ([]CronTemplate, error)
}

// CronTemplate 启动期 LoadAll 的最小载入信息。
type CronTemplate struct {
	TaskID   string
	CronExpr string
}

// Trigger 触发回调：scheduler 到点时调一次（异步，cron.Job goroutine 中）。
// 实现一般是 scan.service.TriggerCronTask(taskID)。
type Trigger func(ctx context.Context, taskID string)

// Scheduler in-process cron 调度器（基于 robfig/cron/v3）。
//
// 接口：
//   - LoadAll(ctx) 启动期一次性装入 PG 中已有 cron task
//   - Add / Remove 单条 task 的注册 / 注销（CreateTask / Cancel / Delete 触发）
//   - Start / Stop 控生命周期
//
// 线程安全：内部用 sync.Mutex 保 entries map；cron 自己 goroutine 安全。
type Scheduler struct {
	cron    *cron.Cron
	listing TaskListing
	trigger Trigger
	logger  *log.Logger

	// PR-S17-RACE：trigger goroutine 用 rootCtx 派生 ctx，shutdown 时统一
	// cancel；不再用 context.Background() 阻断 graceful shutdown。
	rootCtx    context.Context
	rootCancel context.CancelFunc

	mu      sync.Mutex
	entries map[string]cron.EntryID // taskID → cron entry id
}

// New 构造。listing / trigger 不能 nil；logger 可空。
func New(listing TaskListing, trigger Trigger, logger *log.Logger) (*Scheduler, error) {
	if listing == nil || trigger == nil {
		return nil, errx.New(errx.ErrInternal, "scheduler.New: listing / trigger 不能为 nil")
	}
	// 用默认 5 字段 parser（兼容 Linux crontab）；不开秒级
	c := cron.New()
	rootCtx, cancel := context.WithCancel(context.Background())
	return &Scheduler{
		cron:       c,
		listing:    listing,
		trigger:    trigger,
		logger:     logger,
		rootCtx:    rootCtx,
		rootCancel: cancel,
		entries:    make(map[string]cron.EntryID),
	}, nil
}

// LoadAll 启动期一次性把 PG 中所有 cron task 装入。
//
// 已经在 entries 里的会被 Remove + Add 重置。
func (s *Scheduler) LoadAll(ctx context.Context) error {
	if s == nil || s.listing == nil {
		return nil
	}
	tmpls, err := s.listing.ListCronTemplates(ctx)
	if err != nil {
		return err
	}
	loaded := 0
	for i := range tmpls {
		t := &tmpls[i]
		if err := s.Add(t.TaskID, t.CronExpr); err != nil {
			if s.logger != nil {
				s.logger.Warn("scheduler: load cron task failed (skip)",
					"task_id", t.TaskID, "expr", t.CronExpr, "err", err.Error())
			}
			continue
		}
		loaded++
	}
	if s.logger != nil {
		s.logger.Info("scheduler: cron tasks loaded",
			"loaded", loaded, "total_templates", len(tmpls))
	}
	return nil
}

// Add 注册一条 cron task；同 taskID 重复 add 会先 Remove 再 add（覆盖语义）。
func (s *Scheduler) Add(taskID, expr string) error {
	if s == nil {
		return errx.New(errx.ErrInternal, "scheduler: nil")
	}
	if taskID == "" {
		return errx.New(errx.ErrInvalidInput, "scheduler.Add: taskID 不能为空")
	}
	if !domain.ValidCronExpr(expr) {
		return errx.New(errx.ErrInvalidInput, "scheduler.Add: cron_expr 不合法").
			WithFields("expr", expr)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// 已存在 → 先移再加
	if old, ok := s.entries[taskID]; ok {
		s.cron.Remove(old)
		delete(s.entries, taskID)
	}
	id, err := s.cron.AddFunc(expr, s.makeJob(taskID))
	if err != nil {
		return errx.Wrap(errx.ErrInvalidInput, err, "scheduler: AddFunc")
	}
	s.entries[taskID] = id
	return nil
}

// Remove 注销 cron task；taskID 不在 entries 里是 no-op。
func (s *Scheduler) Remove(taskID string) {
	if s == nil || taskID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if id, ok := s.entries[taskID]; ok {
		s.cron.Remove(id)
		delete(s.entries, taskID)
	}
}

// Start 启动调度器；幂等。
func (s *Scheduler) Start() {
	if s == nil {
		return
	}
	s.cron.Start()
}

// Stop 停调度。先 cancel rootCtx 让运行中 trigger 能感知（TriggerCronTask
// 内 CreateTask 会传 ctx 给后续 dispatch）；再等 cron 现有 job goroutine 完成。
func (s *Scheduler) Stop() {
	if s == nil {
		return
	}
	if s.rootCancel != nil {
		s.rootCancel()
	}
	<-s.cron.Stop().Done()
}

// Count 当前注册的 cron task 数；测试 / 监控用。
func (s *Scheduler) Count() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

func (s *Scheduler) makeJob(taskID string) func() {
	return func() {
		// PR-S17-RACE：从 rootCtx 派生，server shutdown → cancel → trigger
		// 内的 service.CreateTask（含 dispatch / ES / asset 写）能及时退出。
		s.trigger(s.rootCtx, taskID)
	}
}
