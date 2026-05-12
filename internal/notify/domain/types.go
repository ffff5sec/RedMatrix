// Package domain notify 模块的领域类型（PR-S25）。
//
// 范围：
//   - Subscription：订阅规则模板（事件 kind + 通道 + 配置）
//   - Delivery：一次具体投递记录（状态机：pending → sent / failed → 重试 / dead）
//   - EventKind / Channel / DeliveryStatus 枚举
//
// 不含传输逻辑（webhook/email adapter 在父包）。
package domain

import (
	"strings"
	"time"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

// EventKind 通知系统识别的事件 kind。
type EventKind string

const (
	// EventTaskCompleted scan task 聚合状态 → completed
	EventTaskCompleted EventKind = "task_completed"
	// EventTaskFailed scan task 聚合状态 → failed / partial_failed
	EventTaskFailed EventKind = "task_failed"
	// EventFindingHigh 高危漏洞发现（nuclei result severity ∈ high/critical）
	EventFindingHigh EventKind = "finding_high"
)

// Valid 判定 EventKind 是否合法值。
func (k EventKind) Valid() bool {
	switch k {
	case EventTaskCompleted, EventTaskFailed, EventFindingHigh:
		return true
	}
	return false
}

// Channel 通知通道类型。
type Channel string

const (
	ChannelWebhook Channel = "webhook"
	ChannelEmail   Channel = "email"
)

// Valid 判定 Channel 是否合法值。
func (c Channel) Valid() bool {
	switch c {
	case ChannelWebhook, ChannelEmail:
		return true
	}
	return false
}

// DeliveryStatus 投递状态机。
type DeliveryStatus string

const (
	DeliveryPending DeliveryStatus = "pending" // 待发送
	DeliverySent    DeliveryStatus = "sent"    // 已成功（终态）
	DeliveryFailed  DeliveryStatus = "failed"  // 失败，等待下次重试
	DeliveryDead    DeliveryStatus = "dead"    // 达到 max attempts，放弃（终态）
)

// Valid 判定 DeliveryStatus 是否合法值。
func (s DeliveryStatus) Valid() bool {
	switch s {
	case DeliveryPending, DeliverySent, DeliveryFailed, DeliveryDead:
		return true
	}
	return false
}

// IsTerminal sent / dead 不再重试。
func (s DeliveryStatus) IsTerminal() bool {
	return s == DeliverySent || s == DeliveryDead
}

// MaxAttempts 一次 delivery 最多尝试次数。达到后 → DeliveryDead。
const MaxAttempts = 5

// RetryBackoffs 第 N 次失败后下一次 attempt 的延迟（index = attempts-1）。
// attempts=1 失败 → 1m 后；attempts=2 → 5m；3 → 30m；4 → 2h；5 直接 dead。
var RetryBackoffs = []time.Duration{
	1 * time.Minute,
	5 * time.Minute,
	30 * time.Minute,
	2 * time.Hour,
	12 * time.Hour,
}

// NextScheduledAt 根据已尝试次数算下次调度时刻。
// attempts ≥ MaxAttempts 时返 nil（表示应转 dead）。
func NextScheduledAt(now time.Time, attempts int) *time.Time {
	if attempts <= 0 || attempts >= MaxAttempts {
		return nil
	}
	idx := attempts - 1
	if idx >= len(RetryBackoffs) {
		idx = len(RetryBackoffs) - 1
	}
	t := now.Add(RetryBackoffs[idx])
	return &t
}

// SubscriptionNameMaxLen schema VARCHAR(128) 对齐。
const SubscriptionNameMaxLen = 128

// Subscription 订阅规则。
type Subscription struct {
	ID         string
	TenantID   string
	ProjectID  *string // nil = 全租户
	Name       string
	EventKinds []EventKind
	Channel    Channel
	Config     map[string]any // webhook: {url, secret?}; email: {to: [..]}
	Filter     map[string]any // {min_severity: "high"} 等
	Enabled    bool
	CreatedBy  string
	CreatedAt  time.Time
	UpdatedAt  time.Time
	DeletedAt  *time.Time
}

// IsDeleted 软删后所有 RPC 返 NotFound。
func (s *Subscription) IsDeleted() bool {
	return s != nil && s.DeletedAt != nil
}

// ValidateForCreate 跑 INSERT 前的全部域内规则。
func (s *Subscription) ValidateForCreate() error {
	if s == nil {
		return errx.New(errx.ErrInvalidInput, "subscription is nil")
	}
	if strings.TrimSpace(s.TenantID) == "" {
		return errx.New(errx.ErrInvalidInput, "subscription.tenant_id 不能为空")
	}
	if strings.TrimSpace(s.Name) == "" {
		return errx.New(errx.ErrInvalidInput, "subscription.name 不能为空")
	}
	if len(s.Name) > SubscriptionNameMaxLen {
		return errx.New(errx.ErrInvalidInput, "subscription.name 超出最大长度").
			WithFields("max", SubscriptionNameMaxLen)
	}
	if len(s.EventKinds) == 0 {
		return errx.New(errx.ErrInvalidInput, "subscription.event_kinds 至少 1 个")
	}
	for _, k := range s.EventKinds {
		if !k.Valid() {
			return errx.New(errx.ErrInvalidInput, "subscription.event_kind 不合法").
				WithFields("got", string(k))
		}
	}
	if !s.Channel.Valid() {
		return errx.New(errx.ErrInvalidInput, "subscription.channel 不合法").
			WithFields("got", string(s.Channel))
	}
	if s.Config == nil {
		s.Config = map[string]any{}
	}
	if s.Filter == nil {
		s.Filter = map[string]any{}
	}

	switch s.Channel {
	case ChannelWebhook:
		url, _ := s.Config["url"].(string)
		if strings.TrimSpace(url) == "" {
			return errx.New(errx.ErrInvalidInput, "webhook subscription config.url 不能为空")
		}
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			return errx.New(errx.ErrInvalidInput, "webhook url 必须以 http(s):// 开头").
				WithFields("url_prefix", "<masked>")
		}
	case ChannelEmail:
		to, _ := s.Config["to"].([]any)
		if len(to) == 0 {
			return errx.New(errx.ErrInvalidInput, "email subscription config.to 至少 1 个邮箱")
		}
		for _, x := range to {
			if addr, ok := x.(string); !ok || strings.TrimSpace(addr) == "" || !strings.Contains(addr, "@") {
				return errx.New(errx.ErrInvalidInput, "email 地址不合法").WithFields("addr", x)
			}
		}
	}
	return nil
}

// Delivery 一次投递记录。
type Delivery struct {
	ID             string
	SubscriptionID string
	TenantID       string
	ProjectID      *string
	EventKind      EventKind
	EventTopic     string
	Payload        map[string]any
	Status         DeliveryStatus
	Attempts       int
	LastError      string
	ScheduledAt    time.Time
	CreatedAt      time.Time
	SentAt         *time.Time
}
