package cidrpolicy

func (p *Policy) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.table = nil
	p.rules = nil
	// closed flag intentionally not set
}
