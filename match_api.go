package cidrpolicy

import "net"

func ruleNet(r Rule) *net.IPNet {
	if len(r.Raw) > 0 {
		_, n, err := net.ParseCIDR(string(r.Raw))
		if err == nil {
			return n
		}
	}
	return r.Net
}

func (p *Policy) Match(ipStr string) (Action, string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return ActionDeny, "", ErrClosed
	}
	// Not yet Init / no table built: return a decidable error instead of
	// panicking on p.table.rules. This guard runs before noteHit so the
	// failure path leaves no half-recorded hit behind — a dirty HitCount
	// or pending buffer would pollute audit, reports and the security board.
	if p.table == nil {
		return ActionDeny, "", ErrNoTable
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ActionDeny, "", ErrInvalid
	}
	// Only count a hit once the table is ready and the IP is valid; every
	// error return above must keep HitCount clean.
	p.noteHit(ipStr)
	for _, r := range p.table.rules {
		n := ruleNet(r)
		if n != nil && n.Contains(ip) {
			return r.Act, r.Name, nil
		}
	}
	return p.defaultAct, "", nil
}
