package cidrpolicy_test

import (
	"errors"
	"testing"

	cidrpolicy "github.com/LYH2263/go-cidrpolicy"
)

func TestBug04_NilTableNoDirtyHit(t *testing.T) {
	p := cidrpolicy.NewPolicy(cidrpolicy.ActionDeny)
	_ = p.AddCIDR("corp", "10.0.0.0/8", cidrpolicy.ActionAllow)
	// force nil table without Init path: new policy with rules cleared table
	p2 := cidrpolicy.NewPolicy(cidrpolicy.ActionDeny)
	var panicked bool
	var err error
	func() {
		defer func() {
			if recover() != nil {
				panicked = true
			}
		}()
		_, _, err = p2.Match("10.1.1.1")
	}()
	if panicked {
		t.Fatal("panic")
	}
	if err == nil || !errors.Is(err, cidrpolicy.ErrNoTable) {
		t.Fatalf("%v", err)
	}
	if p2.HitCount() != 0 {
		t.Fatalf("dirty hits %d", p2.HitCount())
	}
	_ = p
}
