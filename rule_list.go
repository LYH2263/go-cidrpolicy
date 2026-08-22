package cidrpolicy

import "strings"

// ListRules returns an isolated deep copy of the rule list.
// Callers may freely mutate the returned slice (including rule Names used as
// display/filter labels) without polluting the live ruleset: ExportNames and
// Decide read from p.rules and p.table, which share no backing storage with
// the returned slice.
func (p *Policy) ListRules() []Rule {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]Rule, len(p.rules))
	for i, r := range p.rules {
		out[i] = cloneRule(r)
	}
	return out
}

func (p *Policy) SnapshotRaws() [][]byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([][]byte, len(p.rules))
	for i, r := range p.rules {
		out[i] = append([]byte(nil), r.Raw...)
	}
	return out
}

func (p *Policy) ExportNames() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	names := make([]string, 0, len(p.rules))
	for _, r := range p.rules {
		names = append(names, r.Name)
	}
	return strings.Join(names, ",")
}
