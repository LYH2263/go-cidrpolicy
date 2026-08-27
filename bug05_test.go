package cidrpolicy_test

import (
	"errors"
	"testing"

	cidrpolicy "github.com/LYH2263/go-cidrpolicy"
)

func TestBug05_BadCIDRWrapped(t *testing.T) {
	p := cidrpolicy.NewPolicy(cidrpolicy.ActionDeny)
	err := p.AddCIDR("bad", "not-a-cidr", cidrpolicy.ActionAllow)
	if err == nil || !errors.Is(err, cidrpolicy.ErrBadCIDR) {
		t.Fatalf("%v", err)
	}
	err2 := cidrpolicy.WrapBadCIDR(err)
	if !errors.Is(err2, cidrpolicy.ErrBadCIDR) {
		t.Fatalf("wrap %v", err2)
	}
}
