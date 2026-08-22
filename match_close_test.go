package cidrpolicy

import (
	"errors"
	"testing"
)

// TestMatchAfterClose ensures Match returns ErrClosed after the policy is
// closed, regardless of which close path was taken. This is the regression
// for the旁路探活 crash: a closed engine must surface a stable ErrClosed so
// the bypass retry loop can收口, instead of nil-dereferencing an emptied table
// or returning a stray error.
func TestMatchAfterClose(t *testing.T) {
	t.Run("Close", func(t *testing.T) {
		p := NewPolicy(ActionAllow)
		if err := p.AddCIDR("r1", "10.0.0.0/8", ActionAllow); err != nil {
			t.Fatalf("AddCIDR: %v", err)
		}
		p.Close()

		// The probe keeps poking Match after close; it must see ErrClosed,
		// never a panic and never a nil-table dereference.
		for i := 0; i < 3; i++ {
			act, name, err := p.Match("10.1.2.3")
			if !errors.Is(err, ErrClosed) {
				t.Fatalf("iter %d: err = %v, want ErrClosed (act=%v name=%q)", i, err, act, name)
			}
			if act != ActionDeny {
				t.Fatalf("iter %d: act = %v, want ActionDeny on closed", i, act)
			}
			if name != "" {
				t.Fatalf("iter %d: name = %q, want empty on closed", i, name)
			}
		}
	})

	t.Run("CloseFlushCount", func(t *testing.T) {
		p := NewPolicy(ActionAllow)
		if err := p.AddCIDR("r1", "10.0.0.0/8", ActionAllow); err != nil {
			t.Fatalf("AddCIDR: %v", err)
		}
		// seed a pending hit so the flush count path is exercised
		_, _, _ = p.Match("10.1.2.3")
		n := p.CloseFlushCount()
		if n != 1 {
			t.Fatalf("flushed = %d, want 1", n)
		}

		for i := 0; i < 3; i++ {
			act, name, err := p.Match("10.1.2.3")
			if !errors.Is(err, ErrClosed) {
				t.Fatalf("iter %d: err = %v, want ErrClosed (act=%v name=%q)", i, err, act, name)
			}
			if act != ActionDeny {
				t.Fatalf("iter %d: act = %v, want ActionDeny on closed", i, act)
			}
		}
	})

	t.Run("DoubleClose", func(t *testing.T) {
		p := NewPolicy(ActionAllow)
		p.Close()
		p.Close() // must be idempotent, no panic
		if _, _, err := p.Match("10.1.2.3"); !errors.Is(err, ErrClosed) {
			t.Fatalf("after double close: err = %v, want ErrClosed", err)
		}
	})
}

// TestMatchNoTableBeforeInit covers the pre-Init path: Match on a policy with
// no table yet returns ErrNoTable, not a nil-dereference. This keeps the
// "never touch a nil table" invariant explicit.
func TestMatchNoTableBeforeInit(t *testing.T) {
	p := NewPolicy(ActionAllow)
	// deliberately no AddCIDR/Init: table is nil, policy not closed
	act, _, err := p.Match("10.1.2.3")
	if !errors.Is(err, ErrNoTable) {
		t.Fatalf("err = %v, want ErrNoTable (act=%v)", err, act)
	}
}
