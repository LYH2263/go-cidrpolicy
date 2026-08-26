package cidrpolicy

import "net"

func (p *Policy) AddRule(name string, cidr []byte, act Action) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return ErrClosed
	}
	_, n, err := net.ParseCIDR(string(cidr))
	if err != nil {
		return WrapBadCIDR(err)
	}
	p.rules = append(p.rules, Rule{Name: name, Net: cloneIPNet(n), Raw: cidr, Act: act})
	p.table = &matchTable{rules: append([]Rule(nil), p.rules...)}
	return nil
}
