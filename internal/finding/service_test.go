package finding

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ffff5sec/RedMatrix/internal/finding/domain"
	findingrepo "github.com/ffff5sec/RedMatrix/internal/finding/repo"
)

// === stubs ===

type stubFindingRepo struct {
	byID    map[string]*domain.Finding
	byDedup map[string]*domain.Finding
	// PR-S70：记录每次 Upsert 的 finding（不区分 insert/update，按调用顺序）。
	upserted []*domain.Finding
	// PR-S42: 注入 CAS 入口前的并发钩子；测试用它模拟"GetByID 后状态被外部改"
	casPreHook func()
}

func (r *stubFindingRepo) Upsert(_ context.Context, f *domain.Finding) (*domain.Finding, bool, error) {
	if err := f.ValidateForCreate(); err != nil {
		return nil, false, err
	}
	r.upserted = append(r.upserted, f)
	dKey := f.TenantID + "|" + f.ProjectID + "|" + f.DedupKey
	if r.byDedup == nil {
		r.byDedup = map[string]*domain.Finding{}
		r.byID = map[string]*domain.Finding{}
	}
	if existing, ok := r.byDedup[dKey]; ok {
		existing.LastSeenAt = time.Now()
		existing.OccurrenceCount++
		existing.UpdatedAt = time.Now()
		// stub 返同对象（不深拷贝）
		return existing, false, nil
	}
	if f.ID == "" {
		f.ID = "f-" + dKey
	}
	f.CreatedAt = time.Now()
	f.UpdatedAt = f.CreatedAt
	f.FirstSeenAt = f.CreatedAt
	f.LastSeenAt = f.CreatedAt
	f.OccurrenceCount = 1
	r.byDedup[dKey] = f
	r.byID[f.ID] = f
	return f, true, nil
}
func (r *stubFindingRepo) GetByID(_ context.Context, id string) (*domain.Finding, error) {
	f, ok := r.byID[id]
	if !ok {
		return nil, errors.New("not found")
	}
	// PR-S42: 返副本，避免 service 与测试并发改 stub 内对象时互相干扰
	cp := *f
	return &cp, nil
}
func (r *stubFindingRepo) List(_ context.Context, _ findingrepo.FindingFilter, _ findingrepo.Page) ([]*domain.Finding, int, error) {
	out := []*domain.Finding{}
	for _, f := range r.byID {
		out = append(out, f)
	}
	return out, len(out), nil
}
func (r *stubFindingRepo) UpdateStatus(_ context.Context, id string, status domain.FindingStatus) error {
	f, ok := r.byID[id]
	if !ok {
		return errors.New("not found")
	}
	f.Status = status
	f.UpdatedAt = time.Now()
	return nil
}
func (r *stubFindingRepo) UpdateAssignee(_ context.Context, id string, assigneeID *string) error {
	f, ok := r.byID[id]
	if !ok {
		return errors.New("not found")
	}
	f.AssigneeID = assigneeID
	return nil
}
func (r *stubFindingRepo) UpdateStatusCAS(_ context.Context, id string, from, to domain.FindingStatus) (bool, error) {
	if r.casPreHook != nil {
		r.casPreHook()
	}
	f, ok := r.byID[id]
	if !ok {
		return false, errors.New("not found")
	}
	if f.Status != from {
		return false, nil
	}
	f.Status = to
	f.UpdatedAt = time.Now()
	return true, nil
}
func (r *stubFindingRepo) UpdateAssigneeCAS(_ context.Context, id string, from, to *string) (bool, error) {
	if r.casPreHook != nil {
		r.casPreHook()
	}
	f, ok := r.byID[id]
	if !ok {
		return false, errors.New("not found")
	}
	if !ptrEqStr(f.AssigneeID, from) {
		return false, nil
	}
	f.AssigneeID = to
	return true, nil
}
func ptrEqStr(a, b *string) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}
func (r *stubFindingRepo) SoftDelete(_ context.Context, id string) error {
	delete(r.byID, id)
	return nil
}

type stubEventRepo struct {
	events []*domain.FindingEvent
}

func (r *stubEventRepo) Insert(_ context.Context, e *domain.FindingEvent) error {
	if e.ID == "" {
		e.ID = "e-" + string(e.Kind) + "-" + e.FindingID
	}
	e.CreatedAt = time.Now()
	r.events = append(r.events, e)
	return nil
}
func (r *stubEventRepo) ListByFinding(_ context.Context, findingID string) ([]*domain.FindingEvent, error) {
	out := []*domain.FindingEvent{}
	for _, e := range r.events {
		if e.FindingID == findingID {
			out = append(out, e)
		}
	}
	return out, nil
}

// === Tests ===

func newHarness(t *testing.T) (*service, *stubFindingRepo, *stubEventRepo) {
	t.Helper()
	findings := &stubFindingRepo{}
	events := &stubEventRepo{}
	svc, err := New(Deps{Findings: findings, Events: events})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return svc.(*service), findings, events
}

// === Transition 状态机表驱动 ===

func TestCanTransition(t *testing.T) {
	cases := []struct {
		from, to domain.FindingStatus
		want     bool
	}{
		// open
		{domain.FindingOpen, domain.FindingTriaged, true},
		{domain.FindingOpen, domain.FindingFalsePositive, true},
		{domain.FindingOpen, domain.FindingFixed, true},
		{domain.FindingOpen, domain.FindingConfirmed, false}, // 必须先 triaged
		{domain.FindingOpen, domain.FindingOpen, false},      // 同状态不行

		// triaged
		{domain.FindingTriaged, domain.FindingConfirmed, true},
		{domain.FindingTriaged, domain.FindingFalsePositive, true},
		{domain.FindingTriaged, domain.FindingOpen, true},
		{domain.FindingTriaged, domain.FindingFixed, false}, // 必须先 confirmed

		// confirmed
		{domain.FindingConfirmed, domain.FindingFixed, true},
		{domain.FindingConfirmed, domain.FindingFalsePositive, true},
		{domain.FindingConfirmed, domain.FindingOpen, true}, // PR-S38: 直接 reopen 已支持

		// reopen
		{domain.FindingFixed, domain.FindingOpen, true},
		{domain.FindingFalsePositive, domain.FindingOpen, true},
		{domain.FindingFixed, domain.FindingTriaged, false}, // 必须先 reopen 到 open
	}
	for _, c := range cases {
		got := domain.CanTransition(c.from, c.to)
		if got != c.want {
			t.Errorf("CanTransition(%s, %s) = %v, want %v", c.from, c.to, got, c.want)
		}
	}
}

// === UpsertFromResult ===

func TestUpsertFromResult_NewAndDedup(t *testing.T) {
	svc, _, events := newHarness(t)
	req := UpsertFromResultRequest{
		TenantID:   "t1",
		ProjectID:  "p1",
		TemplateID: "CVE-2021-44228",
		Host:       "example.com",
		Severity:   domain.SeverityHigh,
		Title:      "Log4Shell",
	}

	// 首次：新建
	f1, inserted1, err := svc.UpsertFromResult(context.Background(), req)
	if err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	if !inserted1 {
		t.Error("first call should insert")
	}
	if f1.OccurrenceCount != 1 {
		t.Errorf("first occurrence_count = %d, want 1", f1.OccurrenceCount)
	}

	// 第二次：dedup
	f2, inserted2, err := svc.UpsertFromResult(context.Background(), req)
	if err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	if inserted2 {
		t.Error("second call should NOT insert (dedup)")
	}
	if f1.ID != f2.ID {
		t.Errorf("dedup failed: %s != %s", f1.ID, f2.ID)
	}
	if f2.OccurrenceCount != 2 {
		t.Errorf("second occurrence_count = %d, want 2", f2.OccurrenceCount)
	}

	// 事件：1 created + 1 occurrence
	if len(events.events) != 2 {
		t.Fatalf("want 2 events, got %d", len(events.events))
	}
	if events.events[0].Kind != domain.EventCreated {
		t.Errorf("event[0] = %s, want created", events.events[0].Kind)
	}
	if events.events[1].Kind != domain.EventOccurrence {
		t.Errorf("event[1] = %s, want occurrence", events.events[1].Kind)
	}
}

func TestUpsertFromResult_DifferentHost_NoDedup(t *testing.T) {
	svc, _, _ := newHarness(t)
	base := UpsertFromResultRequest{
		TenantID: "t1", ProjectID: "p1", TemplateID: "T1",
		Severity: domain.SeverityHigh, Title: "X",
	}
	base.Host = "a.test"
	f1, _, _ := svc.UpsertFromResult(context.Background(), base)
	base.Host = "b.test"
	f2, _, _ := svc.UpsertFromResult(context.Background(), base)
	if f1.ID == f2.ID {
		t.Error("different host should create different finding")
	}
}

// === Transition + Comment + Assign ===

func TestTransition_HappyPath(t *testing.T) {
	svc, _, events := newHarness(t)
	f, _, _ := svc.UpsertFromResult(context.Background(), UpsertFromResultRequest{
		TenantID: "t1", ProjectID: "p1", TemplateID: "T1", Host: "x.test",
		Severity: domain.SeverityHigh, Title: "X",
	})
	// open → triaged → confirmed → fixed
	_, err := svc.Transition(context.Background(), TransitionRequest{
		ID: f.ID, To: domain.FindingTriaged, ActorID: "u1",
	})
	if err != nil {
		t.Fatalf("triaged: %v", err)
	}
	_, err = svc.Transition(context.Background(), TransitionRequest{
		ID: f.ID, To: domain.FindingConfirmed, ActorID: "u1",
	})
	if err != nil {
		t.Fatalf("confirmed: %v", err)
	}
	_, err = svc.Transition(context.Background(), TransitionRequest{
		ID: f.ID, To: domain.FindingFixed, ActorID: "u1", Comment: "patched",
	})
	if err != nil {
		t.Fatalf("fixed: %v", err)
	}
	if f.Status != domain.FindingFixed {
		t.Errorf("final status = %s, want fixed", f.Status)
	}
	// 事件：1 created + 3 status_change（不数 comment 因为 service 复用 status_change.Body）
	statusEvents := 0
	for _, e := range events.events {
		if e.Kind == domain.EventStatusChange {
			statusEvents++
		}
	}
	if statusEvents != 3 {
		t.Errorf("status_change events = %d, want 3", statusEvents)
	}
}

func TestTransition_InvalidRejected(t *testing.T) {
	svc, _, _ := newHarness(t)
	f, _, _ := svc.UpsertFromResult(context.Background(), UpsertFromResultRequest{
		TenantID: "t1", ProjectID: "p1", TemplateID: "T1", Host: "x.test",
		Severity: domain.SeverityHigh, Title: "X",
	})
	// open → confirmed 不允许（必须先 triaged）
	_, err := svc.Transition(context.Background(), TransitionRequest{
		ID: f.ID, To: domain.FindingConfirmed,
	})
	if err == nil {
		t.Fatal("expected invalid transition error")
	}
}

func TestComment_RecordsEvent(t *testing.T) {
	svc, _, events := newHarness(t)
	f, _, _ := svc.UpsertFromResult(context.Background(), UpsertFromResultRequest{
		TenantID: "t1", ProjectID: "p1", TemplateID: "T1", Host: "x.test",
		Severity: domain.SeverityHigh, Title: "X",
	})
	_, err := svc.Comment(context.Background(), CommentRequest{
		FindingID: f.ID, ActorID: "u1", Body: "reproduced on staging",
	})
	if err != nil {
		t.Fatalf("Comment: %v", err)
	}
	commentEvents := 0
	for _, e := range events.events {
		if e.Kind == domain.EventComment {
			commentEvents++
		}
	}
	if commentEvents != 1 {
		t.Errorf("comment events = %d, want 1", commentEvents)
	}
}

func TestAssign_RecordsEvent(t *testing.T) {
	svc, _, events := newHarness(t)
	f, _, _ := svc.UpsertFromResult(context.Background(), UpsertFromResultRequest{
		TenantID: "t1", ProjectID: "p1", TemplateID: "T1", Host: "x.test",
		Severity: domain.SeverityHigh, Title: "X",
	})
	target := "u2"
	_, err := svc.Assign(context.Background(), AssignRequest{
		ID: f.ID, ActorID: "u1", AssigneeID: &target,
	})
	if err != nil {
		t.Fatalf("Assign: %v", err)
	}
	if f.AssigneeID == nil || *f.AssigneeID != target {
		t.Errorf("assignee = %v, want %s", f.AssigneeID, target)
	}
	assignEvents := 0
	for _, e := range events.events {
		if e.Kind == domain.EventAssigneeChange {
			assignEvents++
		}
	}
	if assignEvents != 1 {
		t.Errorf("assignee_change events = %d, want 1", assignEvents)
	}
}

// TestTransition_CASLost PR-S42：模拟并发——service.GetByID 看到 open，CAS 入口
// 前钩子触发把 status 改为 triaged → CAS matched=false → 返 ErrFindingInvalidTransition
// 且不写 status_change event。
func TestTransition_CASLost(t *testing.T) {
	svc, findings, events := newHarness(t)
	f, _, _ := svc.UpsertFromResult(context.Background(), UpsertFromResultRequest{
		TenantID: "t1", ProjectID: "p1", TemplateID: "T1", Host: "x.test",
		Severity: domain.SeverityHigh, Title: "X",
	})
	// service.Transition 调 CAS 时，stub 钩子触发：先把 status 改成 triaged
	// 模拟另一并发线程已经推进过；service 持有的 cur.Status=open（CAS 的 from）
	// 与 stub 实际 status=triaged 不符 → matched=false
	findings.casPreHook = func() {
		findings.byID[f.ID].Status = domain.FindingTriaged
	}

	_, err := svc.Transition(context.Background(), TransitionRequest{
		ID: f.ID, To: domain.FindingFalsePositive, ActorID: "u1",
	})
	if err == nil {
		t.Fatal("expected CAS-lost invalid transition error")
	}
	// 没有 status_change event 写入
	for _, e := range events.events {
		if e.Kind == domain.EventStatusChange {
			t.Errorf("status_change event leaked despite CAS miss: %+v", e)
		}
	}
}

// TestAssign_CASLost PR-S42：并发改派——service.GetByID 看到 assignee=nil，CAS
// 入口前钩子触发把 assignee 改为 "u-other" → CAS matched=false → 返 InvalidTransition
// 且不写 assignee_change event。
func TestAssign_CASLost(t *testing.T) {
	svc, findings, events := newHarness(t)
	f, _, _ := svc.UpsertFromResult(context.Background(), UpsertFromResultRequest{
		TenantID: "t1", ProjectID: "p1", TemplateID: "T1", Host: "x.test",
		Severity: domain.SeverityHigh, Title: "X",
	})
	other := "u-other"
	findings.casPreHook = func() {
		findings.byID[f.ID].AssigneeID = &other
	}

	target := "u-me"
	_, err := svc.Assign(context.Background(), AssignRequest{
		ID: f.ID, ActorID: "actor", AssigneeID: &target,
	})
	if err == nil {
		t.Fatal("expected CAS-lost assign error")
	}
	// assignee 没被覆盖
	if findings.byID[f.ID].AssigneeID == nil || *findings.byID[f.ID].AssigneeID != other {
		t.Errorf("assignee mutated despite CAS miss: %v", findings.byID[f.ID].AssigneeID)
	}
	for _, e := range events.events {
		if e.Kind == domain.EventAssigneeChange {
			t.Errorf("assignee_change event leaked despite CAS miss: %+v", e)
		}
	}
}

func TestMakeDedupKey_Consistent(t *testing.T) {
	a := domain.MakeDedupKey("CVE-2021-44228", "example.com")
	b := domain.MakeDedupKey("CVE-2021-44228", "example.com")
	if a != b {
		t.Errorf("MakeDedupKey not deterministic: %q != %q", a, b)
	}
	c := domain.MakeDedupKey("CVE-2021-44228", "other.com")
	if a == c {
		t.Errorf("MakeDedupKey should differ on host: both = %q", a)
	}
}

// === PR-S70 AssetID 入参 ===

// TestUpsertFromResult_StoresAssetID 验 service.UpsertFromResult 把 req.AssetID
// 写到落库的 finding.AssetID。
func TestUpsertFromResult_StoresAssetID(t *testing.T) {
	svc, repo, _ := newHarness(t)
	assetID := "a-1"
	_, _, err := svc.UpsertFromResult(context.Background(), UpsertFromResultRequest{
		TenantID: "t1", ProjectID: "p1", TemplateID: "T", Host: "example.com",
		Severity: domain.SeverityMedium, Title: "x",
		AssetID: &assetID,
	})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if len(repo.upserted) != 1 {
		t.Fatalf("want 1 upsert, got %d", len(repo.upserted))
	}
	got := repo.upserted[0].AssetID
	if got == nil || *got != assetID {
		t.Errorf("AssetID 未透传：got=%v want=%q", got, assetID)
	}
}

// TestUpsertFromResult_NoAssetIDStillWorks AssetID 不传时落 nil。
func TestUpsertFromResult_NoAssetIDStillWorks(t *testing.T) {
	svc, repo, _ := newHarness(t)
	_, _, err := svc.UpsertFromResult(context.Background(), UpsertFromResultRequest{
		TenantID: "t1", ProjectID: "p1", TemplateID: "T", Host: "x",
		Severity: domain.SeverityMedium, Title: "x",
	})
	if err != nil {
		t.Fatalf("%v", err)
	}
	if repo.upserted[0].AssetID != nil {
		t.Errorf("AssetID 应保持 nil")
	}
}
