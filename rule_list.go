package cidrpolicy

import "strings"

// ListRules returns deep copies of rules for admin export.
func (p *Policy) ListRules() []Rule {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]Rule, len(p.rules))
	for i, r := range p.rules {
		out[i] = cloneRule(r)
	}
	return out
}

// SnapshotRaws returns deep copies of stored CIDR byte slices.
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
	names := make([]string, len(p.rules))
	for i, r := range p.rules {
		names[i] = r.Name
	}
	return strings.Join(names, ",")
}
