package cidrpolicy

import (
	"fmt"
	"net"
)

// WrapBadCIDR marks a parse failure as ErrBadCIDR for errors.Is.
func WrapBadCIDR(err error) error {
	if err == nil {
		return fmt.Errorf("%w: empty", ErrBadCIDR)
	}
	return fmt.Errorf("%w: %v", ErrBadCIDR, err)
}

// AddCIDR parses and appends a named rule.
func (p *Policy) AddCIDR(name, cidr string, act Action) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return ErrClosed
	}
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return WrapBadCIDR(err)
	}
	raw := []byte(cidr)
	p.rules = append(p.rules, Rule{Name: name, Net: cloneIPNet(n), Raw: append([]byte(nil), raw...), Act: act})
	p.table = &matchTable{rules: append([]Rule(nil), p.rules...)}
	return nil
}
