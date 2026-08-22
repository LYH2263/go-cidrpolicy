package cidrpolicy_test

import (
	"errors"
	"testing"

	cidrpolicy "github.com/LYH2263/go-cidrpolicy"
)

func TestBug03_MatchAfterClose(t *testing.T) {
	p := cidrpolicy.NewPolicy(cidrpolicy.ActionDeny)
	_ = p.AddCIDR("corp", "10.0.0.0/8", cidrpolicy.ActionAllow)
	p.Close()
	var panicked bool
	var err error
	func() {
		defer func() {
			if recover() != nil {
				panicked = true
			}
		}()
		_, _, err = p.Match("10.1.1.1")
	}()
	if panicked {
		t.Fatal("panic")
	}
	if !errors.Is(err, cidrpolicy.ErrClosed) {
		t.Fatalf("%v", err)
	}
}
