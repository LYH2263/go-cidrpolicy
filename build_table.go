package cidrpolicy

import "context"

type Spec struct {
	Name string
	CIDR string
	Act  Action
}

// BuildTable appends many specs, honoring cancellation between items.
func (p *Policy) BuildTable(ctx context.Context, specs []Spec) error {
	for _, s := range specs {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := p.AddCIDR(s.Name, s.CIDR, s.Act); err != nil {
			return err
		}
	}
	return nil
}
