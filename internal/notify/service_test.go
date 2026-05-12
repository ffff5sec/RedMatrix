package notify

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ffff5sec/RedMatrix/internal/notify/domain"
	notifyrepo "github.com/ffff5sec/RedMatrix/internal/notify/repo"
)

// === stubs ===

type stubSubRepo struct {
	subs map[string]*domain.Subscription
}

func (r *stubSubRepo) Insert(_ context.Context, s *domain.Subscription) error {
	if s.ID == "" {
		s.ID = "sub-" + s.Name
	}
	s.CreatedAt = time.Now()
	s.UpdatedAt = s.CreatedAt
	if r.subs == nil {
		r.subs = map[string]*domain.Subscription{}
	}
	r.subs[s.ID] = s
	return nil
}
func (r *stubSubRepo) GetByID(_ context.Context, id string) (*domain.Subscription, error) {
	s, ok := r.subs[id]
	if !ok {
		return nil, errors.New("not found")
	}
	return s, nil
}
func (r *stubSubRepo) List(_ context.Context, _ notifyrepo.SubscriptionFilter, _ notifyrepo.Page) ([]*domain.Subscription, int, error) {
	out := []*domain.Subscription{}
	for _, s := range r.subs {
		out = append(out, s)
	}
	return out, len(out), nil
}
func (r *stubSubRepo) Update(_ context.Context, s *domain.Subscription) error {
	r.subs[s.ID] = s
	return nil
}
func (r *stubSubRepo) SoftDelete(_ context.Context, id string) error {
	delete(r.subs, id)
	return nil
}
func (r *stubSubRepo) ListMatching(_ context.Context, tenantID string, projectID *string, kind domain.EventKind) ([]*domain.Subscription, error) {
	out := []*domain.Subscription{}
	for _, s := range r.subs {
		if !s.Enabled || s.TenantID != tenantID {
			continue
		}
		matched := false
		for _, k := range s.EventKinds {
			if k == kind {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		// project_id 匹配规则
		if projectID == nil || *projectID == "" {
			if s.ProjectID != nil && *s.ProjectID != "" {
				continue
			}
		} else if s.ProjectID != nil && *s.ProjectID != *projectID {
			continue
		}
		out = append(out, s)
	}
	return out, nil
}

type stubDelRepo struct {
	deliveries map[string]*domain.Delivery
	insertOrd  []*domain.Delivery
}

func (r *stubDelRepo) Insert(_ context.Context, d *domain.Delivery) error {
	if d.ID == "" {
		d.ID = "d-" + d.SubscriptionID + "-" + d.EventTopic
	}
	d.CreatedAt = time.Now()
	if r.deliveries == nil {
		r.deliveries = map[string]*domain.Delivery{}
	}
	r.deliveries[d.ID] = d
	r.insertOrd = append(r.insertOrd, d)
	return nil
}
func (r *stubDelRepo) GetByID(_ context.Context, id string) (*domain.Delivery, error) {
	d, ok := r.deliveries[id]
	if !ok {
		return nil, errors.New("not found")
	}
	return d, nil
}
func (r *stubDelRepo) List(_ context.Context, _ notifyrepo.DeliveryFilter, _ notifyrepo.Page) ([]*domain.Delivery, int, error) {
	out := []*domain.Delivery{}
	for _, d := range r.deliveries {
		out = append(out, d)
	}
	return out, len(out), nil
}
func (r *stubDelRepo) FetchDue(_ context.Context, now time.Time, _ int) ([]*domain.Delivery, error) {
	out := []*domain.Delivery{}
	for _, d := range r.deliveries {
		if (d.Status == domain.DeliveryPending || d.Status == domain.DeliveryFailed) && !d.ScheduledAt.After(now) {
			out = append(out, d)
		}
	}
	return out, nil
}
func (r *stubDelRepo) MarkSent(_ context.Context, id string, t time.Time) error {
	d := r.deliveries[id]
	d.Status = domain.DeliverySent
	d.Attempts++
	d.SentAt = &t
	return nil
}
func (r *stubDelRepo) MarkFailed(_ context.Context, id, errMsg string, next *time.Time) error {
	d := r.deliveries[id]
	d.Attempts++
	d.LastError = errMsg
	if next == nil {
		d.Status = domain.DeliveryDead
	} else {
		d.Status = domain.DeliveryFailed
		d.ScheduledAt = *next
	}
	return nil
}

type stubAdapter struct {
	channel domain.Channel
	err     error
	calls   []*domain.Delivery
}

func (a *stubAdapter) Channel() domain.Channel { return a.channel }
func (a *stubAdapter) Send(_ context.Context, _ *domain.Subscription, d *domain.Delivery) error {
	a.calls = append(a.calls, d)
	return a.err
}

// === Tests ===

func newHarness(t *testing.T) (*service, *stubSubRepo, *stubDelRepo, *stubAdapter) {
	t.Helper()
	subs := &stubSubRepo{}
	dels := &stubDelRepo{}
	adapter := &stubAdapter{channel: domain.ChannelWebhook}
	svc, err := New(Deps{
		Subscriptions: subs,
		Deliveries:    dels,
		Adapters:      []ChannelAdapter{adapter},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return svc.(*service), subs, dels, adapter
}

func TestNotify_MatchesSubscription(t *testing.T) {
	svc, subs, dels, _ := newHarness(t)
	pid := "p1"
	_ = subs.Insert(context.Background(), &domain.Subscription{
		TenantID:   "t1",
		ProjectID:  &pid,
		Name:       "sub1",
		EventKinds: []domain.EventKind{domain.EventTaskCompleted},
		Channel:    domain.ChannelWebhook,
		Config:     map[string]any{"url": "https://x.test"},
		Enabled:    true,
	})

	err := svc.Notify(context.Background(), Event{
		Kind:      domain.EventTaskCompleted,
		TenantID:  "t1",
		ProjectID: &pid,
		Payload:   map[string]any{"task_name": "T"},
	})
	if err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if len(dels.insertOrd) != 1 {
		t.Fatalf("want 1 delivery, got %d", len(dels.insertOrd))
	}
	if dels.insertOrd[0].Status != domain.DeliveryPending {
		t.Errorf("want pending, got %s", dels.insertOrd[0].Status)
	}
}

func TestNotify_DifferentTenant_NoMatch(t *testing.T) {
	svc, subs, dels, _ := newHarness(t)
	pid := "p1"
	_ = subs.Insert(context.Background(), &domain.Subscription{
		TenantID:   "tenantA",
		ProjectID:  &pid,
		Name:       "sub1",
		EventKinds: []domain.EventKind{domain.EventTaskCompleted},
		Channel:    domain.ChannelWebhook,
		Config:     map[string]any{"url": "https://x"},
		Enabled:    true,
	})

	_ = svc.Notify(context.Background(), Event{
		Kind:      domain.EventTaskCompleted,
		TenantID:  "tenantB", // 不同租户
		ProjectID: &pid,
	})
	if len(dels.insertOrd) != 0 {
		t.Errorf("want 0 delivery cross-tenant, got %d", len(dels.insertOrd))
	}
}

func TestNotify_DisabledSubscription_NoMatch(t *testing.T) {
	svc, subs, dels, _ := newHarness(t)
	pid := "p1"
	_ = subs.Insert(context.Background(), &domain.Subscription{
		TenantID:   "t1",
		ProjectID:  &pid,
		Name:       "off",
		EventKinds: []domain.EventKind{domain.EventTaskCompleted},
		Channel:    domain.ChannelWebhook,
		Config:     map[string]any{"url": "https://x"},
		Enabled:    false,
	})
	_ = svc.Notify(context.Background(), Event{
		Kind: domain.EventTaskCompleted, TenantID: "t1", ProjectID: &pid,
	})
	if len(dels.insertOrd) != 0 {
		t.Errorf("disabled sub should not produce delivery, got %d", len(dels.insertOrd))
	}
}

func TestNotify_FilterMinSeverity(t *testing.T) {
	svc, subs, dels, _ := newHarness(t)
	pid := "p1"
	_ = subs.Insert(context.Background(), &domain.Subscription{
		TenantID:   "t1",
		ProjectID:  &pid,
		Name:       "high-only",
		EventKinds: []domain.EventKind{domain.EventFindingHigh},
		Channel:    domain.ChannelWebhook,
		Config:     map[string]any{"url": "https://x"},
		Filter:     map[string]any{"min_severity": "high"},
		Enabled:    true,
	})

	// medium severity → should be filtered out
	_ = svc.Notify(context.Background(), Event{
		Kind: domain.EventFindingHigh, TenantID: "t1", ProjectID: &pid,
		Payload: map[string]any{"severity": "medium"},
	})
	if len(dels.insertOrd) != 0 {
		t.Errorf("medium < min_severity=high should not deliver, got %d", len(dels.insertOrd))
	}
	// critical → 通过
	_ = svc.Notify(context.Background(), Event{
		Kind: domain.EventFindingHigh, TenantID: "t1", ProjectID: &pid,
		Payload: map[string]any{"severity": "critical"},
	})
	if len(dels.insertOrd) != 1 {
		t.Errorf("critical should deliver, got %d", len(dels.insertOrd))
	}
}

func TestDispatch_Success(t *testing.T) {
	svc, subs, dels, _ := newHarness(t)
	pid := "p1"
	_ = subs.Insert(context.Background(), &domain.Subscription{
		TenantID:   "t1",
		ProjectID:  &pid,
		Name:       "sub1",
		EventKinds: []domain.EventKind{domain.EventTaskCompleted},
		Channel:    domain.ChannelWebhook,
		Config:     map[string]any{"url": "https://x"},
		Enabled:    true,
	})

	_ = svc.Notify(context.Background(), Event{
		Kind: domain.EventTaskCompleted, TenantID: "t1", ProjectID: &pid,
	})

	sent, failed, err := svc.RunSweeperOnce(context.Background(), 10)
	if err != nil {
		t.Fatalf("RunSweeperOnce: %v", err)
	}
	if sent != 1 || failed != 0 {
		t.Errorf("want sent=1 failed=0, got sent=%d failed=%d", sent, failed)
	}
	d := dels.insertOrd[0]
	if d.Status != domain.DeliverySent {
		t.Errorf("want sent, got %s", d.Status)
	}
}

func TestDispatch_FailureSchedulesRetry(t *testing.T) {
	svc, subs, dels, adapter := newHarness(t)
	adapter.err = errors.New("connection refused")

	pid := "p1"
	_ = subs.Insert(context.Background(), &domain.Subscription{
		TenantID:   "t1",
		ProjectID:  &pid,
		Name:       "sub1",
		EventKinds: []domain.EventKind{domain.EventTaskCompleted},
		Channel:    domain.ChannelWebhook,
		Config:     map[string]any{"url": "https://x"},
		Enabled:    true,
	})

	_ = svc.Notify(context.Background(), Event{
		Kind: domain.EventTaskCompleted, TenantID: "t1", ProjectID: &pid,
	})

	sent, failed, _ := svc.RunSweeperOnce(context.Background(), 10)
	if sent != 0 || failed != 1 {
		t.Errorf("want sent=0 failed=1, got sent=%d failed=%d", sent, failed)
	}
	d := dels.insertOrd[0]
	if d.Status != domain.DeliveryFailed {
		t.Errorf("want failed, got %s", d.Status)
	}
	if d.Attempts != 1 {
		t.Errorf("want attempts=1, got %d", d.Attempts)
	}
	// 下次 schedule 应该在 +1m 内（RetryBackoffs[0]）
	if !d.ScheduledAt.After(time.Now()) {
		t.Errorf("scheduled_at should be in future, got %v", d.ScheduledAt)
	}
}

func TestDispatch_MaxAttemptsTransitionsToDead(t *testing.T) {
	svc, subs, dels, adapter := newHarness(t)
	adapter.err = errors.New("perma fail")

	pid := "p1"
	_ = subs.Insert(context.Background(), &domain.Subscription{
		TenantID:   "t1",
		ProjectID:  &pid,
		Name:       "sub1",
		EventKinds: []domain.EventKind{domain.EventTaskCompleted},
		Channel:    domain.ChannelWebhook,
		Config:     map[string]any{"url": "https://x"},
		Enabled:    true,
	})

	_ = svc.Notify(context.Background(), Event{
		Kind: domain.EventTaskCompleted, TenantID: "t1", ProjectID: &pid,
	})
	d := dels.insertOrd[0]
	// 人工把 attempts 推到 MaxAttempts-1，让下次失败转 dead
	d.Attempts = domain.MaxAttempts - 1
	// 把 scheduled_at 拉回 now 让 FetchDue 看到
	d.ScheduledAt = time.Now().Add(-time.Second)
	d.Status = domain.DeliveryFailed

	_, _, _ = svc.RunSweeperOnce(context.Background(), 10)
	if d.Status != domain.DeliveryDead {
		t.Errorf("want dead, got %s", d.Status)
	}
}

func TestNextScheduledAt_RetuFollowsBackoffs(t *testing.T) {
	now := time.Now()
	cases := []struct {
		attempts int
		wantNil  bool
		approxOK func(time.Time) bool
	}{
		{1, false, func(t time.Time) bool { return t.Sub(now) >= time.Minute && t.Sub(now) <= 2*time.Minute }},
		{2, false, func(t time.Time) bool { return t.Sub(now) >= 5*time.Minute }},
		{5, true, nil},
	}
	for _, c := range cases {
		got := domain.NextScheduledAt(now, c.attempts)
		if c.wantNil {
			if got != nil {
				t.Errorf("attempts=%d want nil, got %v", c.attempts, got)
			}
			continue
		}
		if got == nil || !c.approxOK(*got) {
			t.Errorf("attempts=%d got %v outside expected range", c.attempts, got)
		}
	}
}

func TestSubscription_ValidateForCreate_RejectsBadConfig(t *testing.T) {
	cases := []struct {
		name string
		sub  *domain.Subscription
		ok   bool
	}{
		{"webhook_missing_url", &domain.Subscription{
			TenantID: "t", Name: "n",
			EventKinds: []domain.EventKind{domain.EventTaskCompleted},
			Channel:    domain.ChannelWebhook,
			Config:     map[string]any{},
		}, false},
		{"webhook_bad_url", &domain.Subscription{
			TenantID: "t", Name: "n",
			EventKinds: []domain.EventKind{domain.EventTaskCompleted},
			Channel:    domain.ChannelWebhook,
			Config:     map[string]any{"url": "ftp://x"},
		}, false},
		{"webhook_ok", &domain.Subscription{
			TenantID: "t", Name: "n",
			EventKinds: []domain.EventKind{domain.EventTaskCompleted},
			Channel:    domain.ChannelWebhook,
			Config:     map[string]any{"url": "https://x.test"},
		}, true},
		{"email_no_to", &domain.Subscription{
			TenantID: "t", Name: "n",
			EventKinds: []domain.EventKind{domain.EventTaskCompleted},
			Channel:    domain.ChannelEmail,
			Config:     map[string]any{},
		}, false},
		{"email_ok", &domain.Subscription{
			TenantID: "t", Name: "n",
			EventKinds: []domain.EventKind{domain.EventTaskCompleted},
			Channel:    domain.ChannelEmail,
			Config:     map[string]any{"to": []any{"a@b.test"}},
		}, true},
		{"empty_event_kinds", &domain.Subscription{
			TenantID: "t", Name: "n",
			EventKinds: []domain.EventKind{},
			Channel:    domain.ChannelWebhook,
			Config:     map[string]any{"url": "https://x"},
		}, false},
		{"invalid_event_kind", &domain.Subscription{
			TenantID: "t", Name: "n",
			EventKinds: []domain.EventKind{"bogus"},
			Channel:    domain.ChannelWebhook,
			Config:     map[string]any{"url": "https://x"},
		}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.sub.ValidateForCreate()
			if c.ok && err != nil {
				t.Errorf("want ok, got err=%v", err)
			}
			if !c.ok && err == nil {
				t.Errorf("want err, got nil")
			}
		})
	}
}
