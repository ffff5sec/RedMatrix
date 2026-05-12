// Package notify 实现订阅 + 投递服务（PR-S25）。
//
// 模块结构：
//   - notify/domain：类型定义（EventKind / Channel / Subscription / Delivery）
//   - notify/repo：持久层（订阅表 + 投递表）
//   - notify/ChannelAdapter：单 channel 投递实现接口
//   - notify/Service：协调层。Notify(ev) → 匹配订阅 → INSERT pending → sweeper 异步发送
//
// 重试模型：
//   - 失败时 attempts++，按 RetryBackoffs 计算下次 scheduled_at
//   - 达到 MaxAttempts → status=dead（永不再发）
package notify

import (
	"context"
	"fmt"
	"time"

	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/notify/domain"
	"github.com/ffff5sec/RedMatrix/internal/notify/repo"
)

// Event 通知系统接收的内部事件。
type Event struct {
	Kind      domain.EventKind
	TenantID  string
	ProjectID *string        // nil = 租户级
	Topic     string         // 来自调用方的 outbox topic（仅记录用）
	Payload   map[string]any // 任意 JSON-able 数据；adapter 用于渲染消息
}

// ChannelAdapter 单 channel 的投递实现。
//
// Send 同步返错；nil = 成功；任意 error = 失败（service 据此计算重试调度）。
// adapter 不感知 attempts / dead 概念，仅做"一次 RPC"。
type ChannelAdapter interface {
	Channel() domain.Channel
	Send(ctx context.Context, sub *domain.Subscription, d *domain.Delivery) error
}

// Logger 让 service 可观测（log 接入 standard / structured logger 都行）。
// 与 internal/platform/log.Logger 对齐：只需 LogError 即可（其余 log 直接通过 *log.Logger 调）。
type Logger interface {
	LogError(ctx context.Context, msg string, err error, kv ...any)
}

// Service notify 模块对外服务接口。
type Service interface {
	// === Subscription CRUD ===
	CreateSubscription(ctx context.Context, req CreateSubscriptionRequest) (*domain.Subscription, error)
	GetSubscription(ctx context.Context, id string) (*domain.Subscription, error)
	ListSubscriptions(ctx context.Context, req ListSubscriptionsRequest) (*ListSubscriptionsResult, error)
	UpdateSubscription(ctx context.Context, req UpdateSubscriptionRequest) (*domain.Subscription, error)
	DeleteSubscription(ctx context.Context, id string) error

	// === Delivery ===
	ListDeliveries(ctx context.Context, req ListDeliveriesRequest) (*ListDeliveriesResult, error)

	// === Notify ===
	Notify(ctx context.Context, ev Event) error

	// === Test ===
	// TestSubscription 立即合成一条 test payload 并触发一次同步投递（不走 sweeper）。
	TestSubscription(ctx context.Context, subscriptionID string) error
}

// CreateSubscriptionRequest 入参。
type CreateSubscriptionRequest struct {
	TenantID   string
	ProjectID  *string
	Name       string
	EventKinds []domain.EventKind
	Channel    domain.Channel
	Config     map[string]any
	Filter     map[string]any
	Enabled    bool
	CreatedBy  string
}

// UpdateSubscriptionRequest 入参。
type UpdateSubscriptionRequest struct {
	ID         string
	Name       string
	EventKinds []domain.EventKind
	Channel    domain.Channel
	Config     map[string]any
	Filter     map[string]any
	Enabled    bool
}

// ListSubscriptionsRequest 入参。
type ListSubscriptionsRequest struct {
	TenantID  string
	ProjectID string
	Channel   string
	Keyword   string
	Enabled   *bool
	Page      int
	PageSize  int
}

// ListSubscriptionsResult 分页结果。
type ListSubscriptionsResult struct {
	Subscriptions []*domain.Subscription
	Total         int
	Page          int
	PageSize      int
}

// ListDeliveriesRequest 入参。
type ListDeliveriesRequest struct {
	TenantID       string
	ProjectID      string
	SubscriptionID string
	Status         string
	EventKind      string
	Page           int
	PageSize       int
}

// ListDeliveriesResult 分页结果。
type ListDeliveriesResult struct {
	Deliveries []*domain.Delivery
	Total      int
	Page       int
	PageSize   int
}

// Deps 构造依赖。
type Deps struct {
	Subscriptions repo.SubscriptionRepository
	Deliveries    repo.DeliveryRepository
	Adapters      []ChannelAdapter // 至少 1 个 channel；按 Channel() 索引
	Logger        Logger           // 可选
	Now           func() time.Time // 可选，默认 time.Now（注入用于测试）
}

type service struct {
	subs       repo.SubscriptionRepository
	deliveries repo.DeliveryRepository
	channels   map[domain.Channel]ChannelAdapter
	logger     Logger
	now        func() time.Time
}

// New 构造 Service。
func New(d Deps) (Service, error) {
	if d.Subscriptions == nil || d.Deliveries == nil {
		return nil, errx.New(errx.ErrInternal, "notify.New: repos 不能为空")
	}
	if len(d.Adapters) == 0 {
		return nil, errx.New(errx.ErrInternal, "notify.New: 至少注入 1 个 ChannelAdapter")
	}
	s := &service{
		subs:       d.Subscriptions,
		deliveries: d.Deliveries,
		channels:   make(map[domain.Channel]ChannelAdapter, len(d.Adapters)),
		logger:     d.Logger,
		now:        d.Now,
	}
	if s.now == nil {
		s.now = time.Now
	}
	for _, a := range d.Adapters {
		s.channels[a.Channel()] = a
	}
	return s, nil
}

// === Subscription CRUD ===

func (s *service) CreateSubscription(ctx context.Context, req CreateSubscriptionRequest) (*domain.Subscription, error) {
	sub := &domain.Subscription{
		TenantID:   req.TenantID,
		ProjectID:  req.ProjectID,
		Name:       req.Name,
		EventKinds: req.EventKinds,
		Channel:    req.Channel,
		Config:     req.Config,
		Filter:     req.Filter,
		Enabled:    req.Enabled,
		CreatedBy:  req.CreatedBy,
	}
	if err := s.subs.Insert(ctx, sub); err != nil {
		return nil, err
	}
	return sub, nil
}

func (s *service) GetSubscription(ctx context.Context, id string) (*domain.Subscription, error) {
	return s.subs.GetByID(ctx, id)
}

func (s *service) ListSubscriptions(ctx context.Context, req ListSubscriptionsRequest) (*ListSubscriptionsResult, error) {
	subs, total, err := s.subs.List(ctx, repo.SubscriptionFilter{
		TenantID:  req.TenantID,
		ProjectID: req.ProjectID,
		Channel:   req.Channel,
		Keyword:   req.Keyword,
		Enabled:   req.Enabled,
	}, repo.Page{Page: req.Page, PageSize: req.PageSize})
	if err != nil {
		return nil, err
	}
	return &ListSubscriptionsResult{
		Subscriptions: subs, Total: total,
		Page: maxInt(req.Page, 1), PageSize: pageSizeOrDefault(req.PageSize, 50),
	}, nil
}

func (s *service) UpdateSubscription(ctx context.Context, req UpdateSubscriptionRequest) (*domain.Subscription, error) {
	cur, err := s.subs.GetByID(ctx, req.ID)
	if err != nil {
		return nil, err
	}
	cur.Name = req.Name
	cur.EventKinds = req.EventKinds
	cur.Channel = req.Channel
	cur.Config = req.Config
	cur.Filter = req.Filter
	cur.Enabled = req.Enabled
	if err := s.subs.Update(ctx, cur); err != nil {
		return nil, err
	}
	return cur, nil
}

func (s *service) DeleteSubscription(ctx context.Context, id string) error {
	return s.subs.SoftDelete(ctx, id)
}

// === Delivery 列表 ===

func (s *service) ListDeliveries(ctx context.Context, req ListDeliveriesRequest) (*ListDeliveriesResult, error) {
	ds, total, err := s.deliveries.List(ctx, repo.DeliveryFilter{
		TenantID:       req.TenantID,
		ProjectID:      req.ProjectID,
		SubscriptionID: req.SubscriptionID,
		Status:         req.Status,
		EventKind:      req.EventKind,
	}, repo.Page{Page: req.Page, PageSize: req.PageSize})
	if err != nil {
		return nil, err
	}
	return &ListDeliveriesResult{
		Deliveries: ds, Total: total,
		Page: maxInt(req.Page, 1), PageSize: pageSizeOrDefault(req.PageSize, 50),
	}, nil
}

// === Notify：事件入口 ===

func (s *service) Notify(ctx context.Context, ev Event) error {
	if !ev.Kind.Valid() {
		return errx.New(errx.ErrInvalidInput, "notify.Notify: event_kind 非法").
			WithFields("kind", string(ev.Kind))
	}
	if ev.TenantID == "" {
		return errx.New(errx.ErrInvalidInput, "notify.Notify: tenant_id 不能为空")
	}
	subs, err := s.subs.ListMatching(ctx, ev.TenantID, ev.ProjectID, ev.Kind)
	if err != nil {
		return err
	}
	if len(subs) == 0 {
		return nil // 无订阅 = 静默
	}
	now := s.now()
	for _, sub := range subs {
		// 过滤器：finding_high 时校 payload.severity ≥ sub.filter.min_severity
		if !passesFilter(sub.Filter, ev.Payload) {
			continue
		}
		d := &domain.Delivery{
			SubscriptionID: sub.ID,
			TenantID:       sub.TenantID,
			ProjectID:      ev.ProjectID,
			EventKind:      ev.Kind,
			EventTopic:     ev.Topic,
			Payload:        ev.Payload,
			Status:         domain.DeliveryPending,
			ScheduledAt:    now,
		}
		if err := s.deliveries.Insert(ctx, d); err != nil {
			if s.logger != nil {
				s.logger.LogError(ctx, "notify: insert delivery failed", err,
					"sub_id", sub.ID, "event_kind", string(ev.Kind))
			}
			// 继续处理其它订阅，不中断整批
			continue
		}
	}
	return nil
}

// === Sweeper：定时调度 + dispatch ===

// RunSweeperOnce 拉一批 due delivery 并尝试发送。
// 调用方负责定时器；这里只跑一次。
func (s *service) RunSweeperOnce(ctx context.Context, batchLimit int) (sent, failed int, err error) {
	now := s.now()
	dueList, err := s.deliveries.FetchDue(ctx, now, batchLimit)
	if err != nil {
		return 0, 0, err
	}
	for _, d := range dueList {
		if perr := s.dispatch(ctx, d); perr != nil {
			failed++
		} else {
			sent++
		}
	}
	return sent, failed, nil
}

// dispatch 发送单条 delivery；处理重试 / dead 状态机。
func (s *service) dispatch(ctx context.Context, d *domain.Delivery) error {
	sub, err := s.subs.GetByID(ctx, d.SubscriptionID)
	if err != nil {
		// 订阅被删 → 整条 delivery 转 dead（无路可发）
		_ = s.deliveries.MarkFailed(ctx, d.ID, "subscription deleted", nil)
		return err
	}
	adapter, ok := s.channels[sub.Channel]
	if !ok {
		// 通道未注入 → 立即 dead（人工介入）
		_ = s.deliveries.MarkFailed(ctx, d.ID, "channel adapter not configured: "+string(sub.Channel), nil)
		return errx.New(errx.ErrChannelTypeInvalid, "no adapter for channel").
			WithFields("channel", string(sub.Channel))
	}
	if err := adapter.Send(ctx, sub, d); err != nil {
		nextAttempts := d.Attempts + 1
		next := domain.NextScheduledAt(s.now(), nextAttempts)
		_ = s.deliveries.MarkFailed(ctx, d.ID, err.Error(), next)
		if s.logger != nil {
			s.logger.LogError(ctx, "notify: dispatch failed", err,
				"delivery_id", d.ID, "channel", string(sub.Channel),
				"attempts", nextAttempts)
		}
		return err
	}
	return s.deliveries.MarkSent(ctx, d.ID, s.now())
}

// === Test：合成 payload 立即同步投递 ===

func (s *service) TestSubscription(ctx context.Context, id string) error {
	sub, err := s.subs.GetByID(ctx, id)
	if err != nil {
		return err
	}
	adapter, ok := s.channels[sub.Channel]
	if !ok {
		return errx.New(errx.ErrChannelTypeInvalid, "channel adapter 未配置").
			WithFields("channel", string(sub.Channel))
	}
	d := &domain.Delivery{
		SubscriptionID: sub.ID,
		TenantID:       sub.TenantID,
		ProjectID:      sub.ProjectID,
		EventKind:      domain.EventTaskCompleted, // 测试事件 kind 不重要
		EventTopic:     "notify.test.v1",
		Payload: map[string]any{
			"test":    true,
			"message": fmt.Sprintf("test from RedMatrix subscription %q", sub.Name),
		},
		Status:      domain.DeliveryPending,
		ScheduledAt: s.now(),
	}
	if err := s.deliveries.Insert(ctx, d); err != nil {
		return err
	}
	if err := adapter.Send(ctx, sub, d); err != nil {
		_ = s.deliveries.MarkFailed(ctx, d.ID, err.Error(), nil) // test 不重试
		return errx.New(errx.ErrChannelTestFailed, "test 投递失败："+err.Error())
	}
	_ = s.deliveries.MarkSent(ctx, d.ID, s.now())
	return nil
}

// === 辅助 ===

// passesFilter 仅 finding_high 类目前用到 min_severity；其它 kind 默认通过。
func passesFilter(filter map[string]any, payload map[string]any) bool {
	minSev, ok := filter["min_severity"].(string)
	if !ok || minSev == "" {
		return true
	}
	sev, _ := payload["severity"].(string)
	return severityRank(sev) >= severityRank(minSev)
}

func severityRank(s string) int {
	switch s {
	case "info":
		return 1
	case "low":
		return 2
	case "medium":
		return 3
	case "high":
		return 4
	case "critical":
		return 5
	}
	return 0
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func pageSizeOrDefault(s, def int) int {
	if s <= 0 {
		return def
	}
	return s
}
