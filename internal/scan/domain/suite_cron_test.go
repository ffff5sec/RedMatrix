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
