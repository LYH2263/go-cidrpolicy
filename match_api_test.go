package cidrpolicy

import (
	"errors"
	"testing"
)

// newReadyPolicy builds a policy and immediately runs Init so its match table
// is available. It is the "ready" counterpart to NewPolicy (which leaves
// p.table == nil until Init/AddCIDR/Reload).
func newReadyPolicy(def Action) (*Policy, error) {
	p := NewPolicy(def)
	return p, p.Init()
}

// Regression for the "Match before Init" bug.
//
// Before the fix, Match called noteHit (hits++ / pending append) and only
// then dereferenced p.table.rules. On a freshly-created policy p.table == nil,
// so Match (a) left a half-recorded hit in HitCount/pending and (b) panicked.
// Reports and the security board were polluted with phantom hits, and on-call
// saw inflated numbers. The fix returns ErrNoTable before touching noteHit.
func TestMatchBeforeInitReturnsErrNoTable_NoDirtyHit(t *testing.T) {
	p := NewPolicy(ActionAllow)

	// No Init/AddCIDR/Reload yet -> table is nil.
	act, name, err := p.Match("10.0.0.1")
	if !errors.Is(err, ErrNoTable) {
		t.Fatalf("want ErrNoTable, got act=%v name=%q err=%v", act, name, err)
	}
	if act != ActionDeny {
		t.Fatalf("want ActionDeny on no-table error, got %v", act)
	}

	// Failure path must not leave a dirty hit behind.
	if got := p.HitCount(); got != 0 {
		t.Fatalf("HitCount polluted by failed match: want 0, got %d", got)
	}
	p.mu.Lock()
	pending := len(p.pending)
	p.mu.Unlock()
	if pending != 0 {
		t.Fatalf("pending polluted by failed match: want 0, got %d", pending)
	}

	// A second lookup on the same IP must still report the clean state —
	// no accumulated hit from the prior failure.
	if _, _, err := p.Match("10.0.0.1"); !errors.Is(err, ErrNoTable) {
		t.Fatalf("second match want ErrNoTable, got %v", err)
	}
	if got := p.HitCount(); got != 0 {
		t.Fatalf("HitCount polluted after repeated failure: want 0, got %d", got)
	}
}

// Once Init has run, Match counts hits and resolves rules normally — the
// ErrNoTable guard must not suppress legitimate matching on a ready policy.
func TestMatchAfterInitCountsAndMatches(t *testing.T) {
	p, err := newReadyPolicy(ActionAllow)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := p.AddCIDR("trusted", "10.0.0.0/8", ActionAllow); err != nil {
		t.Fatalf("addcidr: %v", err)
	}

	act, name, err := p.Match("10.0.0.1")
	if err != nil {
		t.Fatalf("ready match: %v", err)
	}
	if act != ActionAllow || name != "trusted" {
		t.Fatalf("want allow/trusted, got act=%v name=%q", act, name)
	}
	if got := p.HitCount(); got != 1 {
		t.Fatalf("HitCount after one ready match: want 1, got %d", got)
	}
}

// Match on a closed policy still surfaces ErrClosed and never counts a hit,
// matching the contract the failure-path ordering preserves.
func TestMatchOnClosedNoHit(t *testing.T) {
	p, _ := newReadyPolicy(ActionAllow)
	p.Close()

	_, _, err := p.Match("10.0.0.1")
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("want ErrClosed, got %v", err)
	}
	if got := p.HitCount(); got != 0 {
		t.Fatalf("HitCount polluted on closed policy: want 0, got %d", got)
	}
}
