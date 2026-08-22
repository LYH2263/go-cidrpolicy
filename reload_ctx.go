package cidrpolicy

import "context"

// ReloadContext reloads rules from path, honoring the caller's cancellation.
// If ctx is cancelled before the table is swapped in, the live rule table is
// left untouched and the context error is returned.
func (p *Policy) ReloadContext(ctx context.Context, path string) error {
	return runReload(ctx, p, path)
}
