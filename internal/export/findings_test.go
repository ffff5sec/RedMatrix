package export

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ffff5sec/RedMatrix/internal/finding"
	"github.com/ffff5sec/RedMatrix/internal/finding/domain"
)

type stubFindingSvc struct {
	pages []*finding.ListFindingsResult
	calls int
	last  finding.ListFindingsRequest
}

func (s *stubFindingSvc) ListFindings(_ context.Context, req finding.ListFindingsRequest) (*finding.ListFindingsResult, error) {
	s.last = req
	if s.calls >= len(s.pages) {
		return &finding.ListFindingsResult{}, nil
	}
	out := s.pages[s.calls]
	s.calls++
	return out, nil
}
func (s *stubFindingSvc) GetFinding(_ context.Context, _ string) (*domain.Finding, error) {
	return nil, nil
}
func (s *stubFindingSvc) ListEvents(_ context.Context, _ string) ([]*domain.FindingEvent, error) {
	return nil, nil
}
func (s *stubFindingSvc) Transition(_ context.Context, _ finding.TransitionRequest) (*domain.Finding, error) {
	return nil, nil
}
func (s *stubFindingSvc) Comment(_ context.Context, _ finding.CommentRequest) (*domain.FindingEvent, error) {
	return nil, nil
}
func (s *stubFindingSvc) Assign(_ context.Context, _ finding.AssignRequest) (*domain.Finding, error) {
	return nil, nil
}
func (s *stubFindingSvc) UpsertFromResult(_ context.Context, _ finding.UpsertFromResultRequest) (*domain.Finding, bool, error) {
	return nil, false, nil
}

func TestFindingsResource_StreamsAllColumns(t *testing.T) {
	fixedTime := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	assigneeID := "u-pa"
	svc := &stubFindingSvc{
		pages: []*finding.ListFindingsResult{
			{Findings: []*domain.Finding{
				{
					ID: "f1", TenantID: "t1", ProjectID: "p1", TemplateID: "CVE-2021-44228",
					Severity: domain.SeverityCritical, Status: domain.FindingOpen,
					Title: "Log4Shell", Host: "10.0.0.1",
					AssigneeID:      &assigneeID,
					OccurrenceCount: 5,
					FirstSeenAt:     fixedTime, LastSeenAt: fixedTime, CreatedAt: fixedTime,
				},
			}},
		},
	}
	res := &FindingsResource{Svc: svc, PageSize: 100}
	var rows []Row
	require.NoError(t, res.Stream(context.Background(),
		Scope{TenantID: "t1", Query: map[string][]string{"severity": {"critical"}}},
		func(r Row) error { rows = append(rows, r); return nil }))

	require.Len(t, rows, 1)
	assert.Equal(t, "f1", rows[0][0])
	assert.Equal(t, "CVE-2021-44228", rows[0][3])
	assert.Equal(t, "critical", rows[0][4])
	assert.Equal(t, "open", rows[0][5])
	assert.Equal(t, "Log4Shell", rows[0][6])
	assert.Equal(t, "u-pa", rows[0][10])
	assert.Equal(t, "5", rows[0][12])
	assert.Equal(t, "critical", svc.last.Severity, "severity 应从 query 透传")
}

func TestFindingsResource_PAZeroProjects_NoFetch(t *testing.T) {
	svc := &stubFindingSvc{}
	res := &FindingsResource{Svc: svc, PageSize: 100}
	err := res.Stream(context.Background(),
		Scope{TenantID: "t1", ProjectIDs: []string{}}, // 显式 0 项目
		func(_ Row) error { t.Fatal("不应 emit"); return nil })
	require.NoError(t, err)
	assert.Zero(t, svc.calls, "PA 0 项目应短路不调 ListFindings")
}
