package cidrpolicy

func (p *Policy) flushPending() int {
	n := len(p.pending)
	p.pending = nil
	return n
}

func (p *Policy) clearRules() {
	p.rules = nil
	p.table = nil
	p.pending = nil
}

func (p *Policy) CloseFlushCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return 0
	}
	p.clearRules()
	n := p.flushPending()
	p.closed = true
	return n
}
