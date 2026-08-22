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
	// Flush pending hits first so the returned count reflects the real number
	// of unflushed records still in the buffer. clearRules() drops p.pending,
	// so flushing after it would always report zero.
	n := p.flushPending()
	p.clearRules()
	p.closed = true
	return n
}
