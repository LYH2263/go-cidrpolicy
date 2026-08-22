package cidrpolicy

func (p *Policy) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	p.closed = true
	p.table = nil
	p.rules = nil
	p.pending = nil
}
