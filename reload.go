package cidrpolicy

import (
	"context"
	"os"
)

func (p *Policy) reloadLocked(data string) error {
	lines, err := parseRuleLines(data)
	if err != nil {
		return err
	}
	p.rules = linesToRules(lines)
	cp := make([]Rule, len(p.rules))
	for i, r := range p.rules {
		cp[i] = cloneRule(r)
	}
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

// Reload replaces rules from a text file; failure leaves prior rules intact.
func (p *Policy) Reload(path string) error {
	return runReload(context.Background(), p, path)
}
