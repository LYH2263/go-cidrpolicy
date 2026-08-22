package cidrpolicy

import (
	"context"
	"errors"
	"testing"
)

// TestBuildTable_RespectsCancelledContext guards against regressing the old
// `_ = ctx` behavior: a pre-canceled context must add no rules and return
// context.Canceled. With the discarded context the whole batch would be built
// and nil returned.
func TestBuildTable_RespectsCancelledContext(t *testing.T) {
	specs := make([]Spec, 100)
	for i := range specs {
		specs[i] = Spec{Name: "r", CIDR: "10.0.0.0/8", Act: ActionDeny}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	p := NewPolicy(ActionDeny)
	err := p.BuildTable(ctx, specs)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if n := p.RuleCount(); n != 0 {
		t.Fatalf("RuleCount = %d, want 0 (cancel must short-circuit before any add)", n)
	}
}

// TestBuildTable_StopsMidBatchOnCancel verifies cancellation is re-checked
// *inside* the loop, not just once before it. A background poller cancels once
// some rules have landed; the loop must stop well short of the full batch.
func TestBuildTable_StopsMidBatchOnCancel(t *testing.T) {
	const total = 5000
	const tripAt = 50
	specs := make([]Spec, total)
	for i := range specs {
		specs[i] = Spec{Name: "r", CIDR: "10.0.0.0/8", Act: ActionDeny}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := NewPolicy(ActionDeny)
	done := make(chan struct{})
	go func() {
		defer close(done)
		err := p.BuildTable(ctx, specs)
		if !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled", err)
		}
	}()

	// Trip the cancel once a handful of rules have been committed.
	for {
		if p.RuleCount() >= tripAt {
			cancel()
			break
		}
		if ctx.Err() != nil {
			t.Fatal("context canceled before tripAt rules were added")
		}
	}
	<-done

	if n := p.RuleCount(); n >= total {
		t.Fatalf("RuleCount = %d, want < %d (loop ran the full batch despite cancel)", n, total)
	}
}
