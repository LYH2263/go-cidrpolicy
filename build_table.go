package cidrpolicy

import "context"

type Spec struct {
	Name string
	CIDR string
	Act  Action
}

func (p *Policy) BuildTable(ctx context.Context, specs []Spec) error {
	_ = ctx
	for _, s := range specs {
		if err := p.AddCIDR(s.Name, s.CIDR, s.Act); err != nil {
			return err
		}
	}
	return nil
}
