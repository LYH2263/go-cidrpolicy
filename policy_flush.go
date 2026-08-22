package cidrpolicy

func (p *Policy) flushPending() int {
	n := len(p.pending)
	p.pending = nil
	return n
}

// clearRules releases rule state. Callers must already hold p.mu.
// It does not touch the closed flag — closure is owned by Close/CloseFlushCount.
func (p *Policy) clearRules() {
	p.rules = nil
	p.table = nil
	p.pending = nil
}

// CloseFlushCount flushes pending hit records then closes the policy.
// The closed flag is set so that later Match calls return ErrClosed
// instead of dereferencing a nil table.
func (p *Policy) CloseFlushCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return 0
	}
	n := p.flushPending()
	p.clearRules()
	p.closed = true
	return n
}
