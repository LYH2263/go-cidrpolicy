package cidrpolicy_test

import (
	"testing"

	cidrpolicy "github.com/LYH2263/go-cidrpolicy"
)

func TestBug10_CloseFlushesPendingFirst(t *testing.T) {
	p := cidrpolicy.NewPolicy(cidrpolicy.ActionDeny)
	if err := p.AddCIDR("corp", "10.0.0.0/8", cidrpolicy.ActionAllow); err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.Match("10.1.1.1"); err != nil {
		t.Fatal(err)
	}
	if p.CloseFlushCount() == 0 {
		t.Fatal("want flush")
	}
}
