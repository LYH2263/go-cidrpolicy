package cidrpolicy

import (
	"context"
	"os"
)

// buildReloadState parses data into a fresh rule set and a compiled match table
// without touching the policy's live state. Building the candidate outside the
// lock means a cancelled caller never observes a half-swapped table: if the
// reload is discarded, the candidate is simply dropped. Safe to call without
// holding p.mu.
func buildReloadState(data string) ([]Rule, *matchTable, error) {
	lines, err := parseRuleLines(data)
	if err != nil {
		return nil, nil, err
	}
	rules := linesToRules(lines)
	cp := make([]Rule, len(rules))
	for i, r := range rules {
		cp[i] = cloneRule(r)
	}
	return rules, &matchTable{rules: cp}, nil
}

func runReload(ctx context.Context, p *Policy, path string) error {
	// A cancelled reload must leave the live table untouched: bail before any
	// work so the caller's "取消重载" is honored immediately.
	if err := ctx.Err(); err != nil {
		return err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	// Re-check after the (potentially slow) read: the caller may have cancelled
	// while the file was being loaded.
	if err := ctx.Err(); err != nil {
		return err
	}
	rules, table, err := buildReloadState(string(b))
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return ErrClosed
	}
	// Final check under the lock: if the caller cancelled while we were waiting
	// for the mutex, drop the candidate and keep the current table rather than
	// pushing a half-built rule set onto production traffic.
	if err := ctx.Err(); err != nil {
		return err
	}
	p.rules = rules
	p.table = table
	return nil
}

func (p *Policy) Reload(path string) error {
	return runReload(context.Background(), p, path)
}
