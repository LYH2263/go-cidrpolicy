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
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ActionDeny, "", ErrInvalid
	}
	p.noteHit(ipStr)
	for _, r := range p.table.rules {
		n := ruleNet(r)
		if n != nil && n.Contains(ip) {
			return r.Act, r.Name, nil
		}
	}
	return p.defaultAct, "", nil
}
