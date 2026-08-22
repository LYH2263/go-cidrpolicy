package cidrpolicy

import "net"

// AddRule registers a CIDR rule from raw bytes; caller buffer must not alias internals.
func (p *Policy) AddRule(name string, cidr []byte, act Action) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return ErrClosed
	}
	raw := append([]byte(nil), cidr...)
	_, n, err := net.ParseCIDR(string(raw))
	if err != nil {
		return WrapBadCIDR(err)
	}
	p.rules = append(p.rules, Rule{Name: name, Net: cloneIPNet(n), Raw: raw, Act: act})
	p.table = &matchTable{rules: append([]Rule(nil), p.rules...)}
	return nil
}
