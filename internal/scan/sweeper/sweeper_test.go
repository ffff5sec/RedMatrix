package sweeper

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type fakeSvc struct {
	calls   atomic.Int32
	swept   int
	err     error
	timeout time.Duration
}

func (f *fakeSvc) SweepStaleAssignments(_ context.Context, timeout time.Duration) (int, error) {
	f.calls.Add(1)
	f.timeout = timeout
	return f.swept, f.err
}

func TestSweeper_TickFiresOnceImmediate(t *testing.T) {
	svc := &fakeSvc{swept: 2}
	s := New(svc, 50*time.Millisecond, time.Minute, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_ = s.Run(ctx)
	if svc.calls.Load() == 0 {
		t.Fatal("expected at least one immediate tick")
	}
	if svc.timeout != time.Minute {
		t.Errorf("timeout passed wrong: %v", svc.timeout)
	}
}

func TestSweeper_RepeatsOnInterval(t *testing.T) {
	svc := &fakeSvc{}
	s := New(svc, 30*time.Millisecond, time.Minute, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 110*time.Millisecond)
	defer cancel()
	_ = s.Run(ctx)
	if svc.calls.Load() < 3 {
		t.Errorf("expected ≥3 ticks (immediate + 2 ticks), got %d", svc.calls.Load())
	}
}

func TestSweeper_ErrorContinues(t *testing.T) {
	svc := &fakeSvc{err: errors.New("boom")}
	s := New(svc, 30*time.Millisecond, time.Minute, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	_ = s.Run(ctx)
	if svc.calls.Load() < 2 {
		t.Errorf("expected continued ticks despite error, got %d", svc.calls.Load())
	}
}

func TestSweeper_DefaultsApplied(t *testing.T) {
	svc := &fakeSvc{}
	s := New(svc, 0, 0, nil)
	if s.interval != DefaultInterval {
		t.Errorf("interval default: %v", s.interval)
	}
	if s.timeout != DefaultTimeout {
		t.Errorf("timeout default: %v", s.timeout)
	}
}

func TestSweeper_NilSvc_NoOp(t *testing.T) {
	s := New(nil, 30*time.Millisecond, time.Minute, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := s.Run(ctx); err != nil {
		t.Fatalf("nil svc Run: %v", err)
	}
}
