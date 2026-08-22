package cidrpolicy

import (
	"context"
	"os"
)

func (p *Policy) reloadLocked(data string) error {
	lines, err := parseRuleLines(data)
	if err != nil {
		// Parse failed: leave the live rule set and match table at the
		// pre-reload snapshot. parseRuleLines returns whatever it parsed
		// before the bad line together with the error; committing those
		// partial rules would expose a half-updated table to traffic that
		// may have been allowed before, silently denying it.
		return err
	}
	rules := linesToRules(lines)
	cp := make([]Rule, len(rules))
	for i, r := range rules {
		cp[i] = cloneRule(r)
	}
	// Swap in the fully built replacement only once parse succeeds. Both
	// fields are written under p.mu, so a concurrent Match observes either
	// the old snapshot or the new one in full, never a mix.
	p.rules = rules
	p.table = &matchTable{rules: cp}
	return nil
}

func runReload(ctx context.Context, p *Policy, path string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return ErrClosed
	}
	return p.reloadLocked(string(b))
}

func (p *Policy) Reload(path string) error {
	return runReload(context.Background(), p, path)
}
