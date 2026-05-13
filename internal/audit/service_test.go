// audit/service_test.go PR-S44 —— 审计 service 单测。
//
// 覆盖：
//   - Log: 输入校验（空 tenant / 非法 action）
//   - Log: 首条用 GenesisPrevHash；后续 prev_hash = 上一条 hash（链）
//   - Log: 不同 tenant 不互相影响（per-tenant 链）
//   - VerifyChain: 全链完整时 ok=true
//   - VerifyChain: 任一行 hash 被改 → ok=false + breakAtIndex 指向首个不连续行
//   - ListLogs: 透传 filter + page，默认 page/pageSize 兜底
package audit

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ffff5sec/RedMatrix/internal/audit/domain"
	"github.com/ffff5sec/RedMatrix/internal/audit/repo"
	"github.com/ffff5sec/RedMatrix/internal/errx"
)

// === stub Repository ===

type stubRepo struct {
	mu     sync.Mutex
	rows   []*domain.AuditLog // 按 insert 顺序
	byID   map[string]*domain.AuditLog
	insErr error // 注入插入失败
}

func newStubRepo() *stubRepo {
	return &stubRepo{byID: map[string]*domain.AuditLog{}}
}

func (r *stubRepo) Insert(_ context.Context, a *domain.AuditLog) error {
	if r.insErr != nil {
		return r.insErr
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if a.ID == "" {
		a.ID = "id-" + a.Hash[:8]
	}
	r.rows = append(r.rows, a)
	r.byID[a.ID] = a
	return nil
}

func (r *stubRepo) GetByID(_ context.Context, id string) (*domain.AuditLog, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.byID[id]
	if !ok {
		return nil, errx.New(errx.ErrAuditLogNotFound, "not found")
	}
	return a, nil
}

func (r *stubRepo) LatestHash(_ context.Context, tenantID string) (string, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := len(r.rows) - 1; i >= 0; i-- {
		if r.rows[i].TenantID == tenantID {
			return r.rows[i].Hash, true, nil
		}
	}
	return domain.GenesisPrevHash, false, nil
}

func (r *stubRepo) List(_ context.Context, filter repo.LogFilter, page repo.Page) ([]*domain.AuditLog, int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []*domain.AuditLog{}
	for _, a := range r.rows {
		if filter.TenantID != "" && a.TenantID != filter.TenantID {
			continue
		}
		if filter.Action != "" && string(a.Action) != filter.Action {
			continue
		}
		out = append(out, a)
	}
	_ = page
	return out, len(out), nil
}

func (r *stubRepo) ListSegmentASC(_ context.Context, tenantID string, from, to time.Time, limit int) ([]*domain.AuditLog, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []*domain.AuditLog{}
	for _, a := range r.rows {
		if a.TenantID != tenantID {
			continue
		}
		if !from.IsZero() && a.CreatedAt.Before(from) {
			continue
		}
		if !to.IsZero() && a.CreatedAt.After(to) {
			continue
		}
		out = append(out, a)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

// === stub Logger ===

type stubLogger struct {
	errors int
}

func (l *stubLogger) LogError(_ context.Context, _ string, _ error, _ ...any) {
	l.errors++
}

// === helpers ===

func newSvc(t *testing.T) (*service, *stubRepo, *stubLogger) {
	t.Helper()
	r := newStubRepo()
	lg := &stubLogger{}
	svc, err := New(r, lg)
	require.NoError(t, err)
	// 单调时间，避免同 createdAt 撞 hash 重复
	var i int64
	base := time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC)
	svc.(*service).now = func() time.Time {
		i++
		return base.Add(time.Duration(i) * time.Millisecond)
	}
	return svc.(*service), r, lg
}

// === Tests ===

func TestLog_EmptyTenant_Rejected(t *testing.T) {
	svc, _, _ := newSvc(t)
	err := svc.Log(context.Background(), LogEvent{
		Action: domain.ActionLogin, ResourceKind: "session",
	})
	require.Error(t, err)
	code, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrInvalidInput, code)
}

func TestLog_InvalidAction_Rejected(t *testing.T) {
	svc, _, _ := newSvc(t)
	err := svc.Log(context.Background(), LogEvent{
		TenantID: "t1", Action: domain.ActionKind("not_a_real_action"), ResourceKind: "x",
	})
	require.Error(t, err)
	code, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrInvalidInput, code)
}

// TestLog_ChainsHashAcrossInserts —— 验证 hash 链：第二条 prev_hash = 第一条 hash，
// 第三条 prev_hash = 第二条 hash。首条 prev_hash = GenesisPrevHash。
func TestLog_ChainsHashAcrossInserts(t *testing.T) {
	svc, repo, _ := newSvc(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		err := svc.Log(ctx, LogEvent{
			TenantID:      "t1",
			Action:        domain.ActionLogin,
			ResourceKind:  "session",
			ActorUsername: "alice",
		})
		require.NoError(t, err)
	}
	require.Len(t, repo.rows, 3)
	assert.Equal(t, domain.GenesisPrevHash, repo.rows[0].PrevHash, "首条用 Genesis 占位")
	assert.Equal(t, repo.rows[0].Hash, repo.rows[1].PrevHash, "第二条 prev = 第一条 hash")
	assert.Equal(t, repo.rows[1].Hash, repo.rows[2].PrevHash, "第三条 prev = 第二条 hash")
	// 每条 hash 都是合法 sha256 hex
	for i, r := range repo.rows {
		assert.Len(t, r.Hash, 64, "row %d hash 长度", i)
	}
}

// TestLog_PerTenantChainsAreIndependent —— 两个 tenant 各自独立的链。
// 不同 tenant 的写入不互相进入对方链 (prev_hash)。
func TestLog_PerTenantChainsAreIndependent(t *testing.T) {
	svc, repo, _ := newSvc(t)
	ctx := context.Background()
	// 交错写入 t1 / t2 / t1 / t2
	for i := 0; i < 2; i++ {
		require.NoError(t, svc.Log(ctx, LogEvent{TenantID: "t1", Action: domain.ActionLogin, ResourceKind: "session"}))
		require.NoError(t, svc.Log(ctx, LogEvent{TenantID: "t2", Action: domain.ActionLogin, ResourceKind: "session"}))
	}
	require.Len(t, repo.rows, 4)
	t1Rows := filterTenant(repo.rows, "t1")
	t2Rows := filterTenant(repo.rows, "t2")
	require.Len(t, t1Rows, 2)
	require.Len(t, t2Rows, 2)
	// t1 链：首条 Genesis，第二条 = 前一条 t1.hash（不是 t2 的）
	assert.Equal(t, domain.GenesisPrevHash, t1Rows[0].PrevHash)
	assert.Equal(t, t1Rows[0].Hash, t1Rows[1].PrevHash)
	assert.Equal(t, domain.GenesisPrevHash, t2Rows[0].PrevHash)
	assert.Equal(t, t2Rows[0].Hash, t2Rows[1].PrevHash)
	// 交叉断言：t1 第二条 prev ≠ t2 任一条 hash
	for _, r := range t2Rows {
		assert.NotEqual(t, r.Hash, t1Rows[1].PrevHash, "t1 链不应吸入 t2 hash")
	}
}

func TestLog_InsertError_PropagatesAndLogged(t *testing.T) {
	svc, repo, lg := newSvc(t)
	repo.insErr = errx.New(errx.ErrDatabase, "pg unavailable")
	err := svc.Log(context.Background(), LogEvent{
		TenantID: "t1", Action: domain.ActionLogin, ResourceKind: "session",
	})
	require.Error(t, err)
	assert.Equal(t, 1, lg.errors, "失败应通过 logger.LogError 上报")
}

// TestVerifyChain_OK_FullSegment —— 写 5 条，全链完整 → ok=true，total=5。
func TestVerifyChain_OK_FullSegment(t *testing.T) {
	svc, _, _ := newSvc(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		require.NoError(t, svc.Log(ctx, LogEvent{
			TenantID: "t1", Action: domain.ActionLogin, ResourceKind: "session",
		}))
	}
	res, err := svc.VerifyChain(ctx, VerifyChainRequest{TenantID: "t1", Limit: 100})
	require.NoError(t, err)
	assert.True(t, res.OK)
	assert.Equal(t, 5, res.Total)
}

// TestVerifyChain_DetectsTampering_HashField —— 改第 3 条的 Payload，重算 hash 失配 → ok=false。
func TestVerifyChain_DetectsTampering_HashField(t *testing.T) {
	svc, repo, _ := newSvc(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		require.NoError(t, svc.Log(ctx, LogEvent{
			TenantID: "t1", Action: domain.ActionLogin, ResourceKind: "session",
		}))
	}
	// 篡改第 3 条（index 2）：改 payload，hash 字段不动 → 重算与 hash 不符
	repo.rows[2].Payload = map[string]any{"tampered": true}

	res, err := svc.VerifyChain(ctx, VerifyChainRequest{TenantID: "t1", Limit: 100})
	require.NoError(t, err)
	assert.False(t, res.OK, "tampered row 应被识破")
	assert.Equal(t, 2, res.BreakAtIndex, "断点应在 index=2")
	assert.NotEmpty(t, res.BreakAtID)
}

// TestVerifyChain_DetectsTampering_PrevHashLink —— 改第 3 条的 PrevHash 字段
// （它自己的 hash 仍能算出，但与上一条的 hash 不再相等）→ ok=false。
func TestVerifyChain_DetectsTampering_PrevHashLink(t *testing.T) {
	svc, repo, _ := newSvc(t)
	ctx := context.Background()
	for i := 0; i < 4; i++ {
		require.NoError(t, svc.Log(ctx, LogEvent{
			TenantID: "t1", Action: domain.ActionLogin, ResourceKind: "session",
		}))
	}
	repo.rows[2].PrevHash = strings.Repeat("f", 64) // 替换为假值

	res, err := svc.VerifyChain(ctx, VerifyChainRequest{TenantID: "t1", Limit: 100})
	require.NoError(t, err)
	assert.False(t, res.OK)
	assert.Equal(t, 2, res.BreakAtIndex)
}

func TestVerifyChain_EmptyTenant_Rejected(t *testing.T) {
	svc, _, _ := newSvc(t)
	_, err := svc.VerifyChain(context.Background(), VerifyChainRequest{TenantID: "  "})
	require.Error(t, err)
	code, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrInvalidInput, code)
}

func TestListLogs_DefaultPaginationFallback(t *testing.T) {
	svc, _, _ := newSvc(t)
	ctx := context.Background()
	require.NoError(t, svc.Log(ctx, LogEvent{TenantID: "t1", Action: domain.ActionLogin, ResourceKind: "session"}))

	res, err := svc.ListLogs(ctx, ListLogsRequest{TenantID: "t1"})
	require.NoError(t, err)
	assert.Equal(t, 1, res.Page, "默认 page=1")
	assert.Equal(t, 50, res.PageSize, "默认 pageSize=50")
	assert.Len(t, res.Logs, 1)
}

// === utils ===

func filterTenant(rows []*domain.AuditLog, tenant string) []*domain.AuditLog {
	out := []*domain.AuditLog{}
	for _, r := range rows {
		if r.TenantID == tenant {
			out = append(out, r)
		}
	}
	return out
}
