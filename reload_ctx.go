package cidrpolicy

import "context"

func (p *Policy) ReloadContext(ctx context.Context, path string) error {
	return runReload(ctx, p, path)
}
