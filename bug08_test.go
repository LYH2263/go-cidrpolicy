package cidrpolicy_test

import (
	"context"
	"fmt"
	"testing"

	cidrpolicy "github.com/LYH2263/go-cidrpolicy"
)

func TestBug08_BuildTableHonorsCancel(t *testing.T) {
	p := cidrpolicy.NewPolicy(cidrpolicy.ActionDeny)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	specs := make([]cidrpolicy.Spec, 40)
	for i := range specs {
		specs[i] = cidrpolicy.Spec{
			Name: fmt.Sprintf("r%d", i),
			CIDR: fmt.Sprintf("10.%d.0.0/16", i),
			Act:  cidrpolicy.ActionAllow,
		}
	}
	if err := p.BuildTable(ctx, specs); err == nil {
		t.Fatal("want cancel")
	}
}
