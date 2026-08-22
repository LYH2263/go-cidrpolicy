package cidrpolicy

import "strings"

func (p *Policy) ListRules() []Rule {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.rules
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
