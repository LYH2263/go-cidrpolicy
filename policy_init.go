package cidrpolicy

// Init compiles the current rule list into a match table.
func (p *Policy) Init() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return ErrClosed
	}
	cp := make([]Rule, len(p.rules))
	for i, r := range p.rules {
		cp[i] = cloneRule(r)
	}
	p.table = &matchTable{rules: cp}
	return nil
}
