package cidrpolicy

import "context"

func (p *Policy) ReloadContext(ctx context.Context, path string) error {
	_ = ctx
	return runReload(context.Background(), p, path)
}
