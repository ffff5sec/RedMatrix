package domain

import "testing"

// PR-S30 测试套件 cron 字段在 ValidateForCreate 的行为。

func TestScanSuite_Cron_Immediate_NoExpr_OK(t *testing.T) {
	pid := "p-1"
	s := &ScanSuite{
		TenantID: "t-1", ProjectID: &pid, Name: "S",
		Kinds: []TaskKind{KindPortScan}, TargetKind: TargetHost,
		ScheduleKind: ScheduleImmediate,
	}
	if err := s.ValidateForCreate(); err != nil {
		t.Errorf("immediate 不需 cron_expr，应通过: %v", err)
	}
}

func TestScanSuite_Cron_MissingExpr_Rejected(t *testing.T) {
	pid := "p-1"
	s := &ScanSuite{
		TenantID: "t-1", ProjectID: &pid, Name: "S",
		Kinds: []TaskKind{KindPortScan}, TargetKind: TargetHost,
		ScheduleKind:   ScheduleCron,
		CronExpr:       "",
		DefaultTargets: []string{"example.com"},
	}
	if err := s.ValidateForCreate(); err == nil {
		t.Error("cron 缺 cron_expr 应失败")
	}
}

func TestScanSuite_Cron_InvalidExpr_Rejected(t *testing.T) {
	pid := "p-1"
	s := &ScanSuite{
		TenantID: "t-1", ProjectID: &pid, Name: "S",
		Kinds: []TaskKind{KindPortScan}, TargetKind: TargetHost,
		ScheduleKind:   ScheduleCron,
		CronExpr:       "garbage cron",
		DefaultTargets: []string{"example.com"},
	}
	if err := s.ValidateForCreate(); err == nil {
		t.Error("非法 cron_expr 应失败")
	}
}

func TestScanSuite_Cron_MissingDefaultTargets_Rejected(t *testing.T) {
	pid := "p-1"
	s := &ScanSuite{
		TenantID: "t-1", ProjectID: &pid, Name: "S",
		Kinds: []TaskKind{KindPortScan}, TargetKind: TargetHost,
		ScheduleKind:   ScheduleCron,
		CronExpr:       "0 2 * * *",
		DefaultTargets: nil,
	}
	if err := s.ValidateForCreate(); err == nil {
		t.Error("cron 缺 default_targets 应失败")
	}
}

func TestScanSuite_Cron_Valid_OK(t *testing.T) {
	pid := "p-1"
	s := &ScanSuite{
		TenantID: "t-1", ProjectID: &pid, Name: "S",
		Kinds: []TaskKind{KindPortScan, KindFingerprint}, TargetKind: TargetHost,
		ScheduleKind:   ScheduleCron,
		CronExpr:       "0 2 * * *",
		DefaultTargets: []string{"example.com", "10.0.0.0/24"},
	}
	if err := s.ValidateForCreate(); err != nil {
		t.Errorf("合法 cron suite 应通过: %v", err)
	}
}

// PR-S34 增量模式校验：cron + incremental → 不需 default_targets。

func TestScanSuite_Cron_Incremental_NoTargets_OK(t *testing.T) {
	pid := "p-1"
	s := &ScanSuite{
		TenantID: "t-1", ProjectID: &pid, Name: "S",
		Kinds: []TaskKind{KindPortScan}, TargetKind: TargetHost,
		ScheduleKind:         ScheduleCron,
		CronExpr:             "0 2 * * *",
		Incremental:          true,
		IncrementalStaleDays: 14,
		// DefaultTargets 空也允许
	}
	if err := s.ValidateForCreate(); err != nil {
		t.Errorf("incremental cron 不需 default_targets, 应通过: %v", err)
	}
	if s.IncrementalStaleDays != 14 {
		t.Errorf("staleDays 应保 14, got %d", s.IncrementalStaleDays)
	}
}

func TestScanSuite_Cron_NonIncremental_StillRequiresTargets(t *testing.T) {
	pid := "p-1"
	s := &ScanSuite{
		TenantID: "t-1", ProjectID: &pid, Name: "S",
		Kinds: []TaskKind{KindPortScan}, TargetKind: TargetHost,
		ScheduleKind: ScheduleCron,
		CronExpr:     "0 2 * * *",
		// Incremental=false 且 DefaultTargets 空 → 仍应失败
	}
	if err := s.ValidateForCreate(); err == nil {
		t.Error("非增量 cron + 空 default_targets 应失败")
	}
}

func TestScanSuite_Cron_Incremental_DefaultStaleDays(t *testing.T) {
	pid := "p-1"
	s := &ScanSuite{
		TenantID: "t-1", ProjectID: &pid, Name: "S",
		Kinds: []TaskKind{KindPortScan}, TargetKind: TargetHost,
		ScheduleKind: ScheduleCron,
		CronExpr:     "0 2 * * *",
		Incremental:  true,
		// IncrementalStaleDays = 0 → 默认 7
	}
	if err := s.ValidateForCreate(); err != nil {
		t.Fatalf("应通过: %v", err)
	}
	if s.IncrementalStaleDays != 7 {
		t.Errorf("默认 stale_days 应为 7, got %d", s.IncrementalStaleDays)
	}
}
