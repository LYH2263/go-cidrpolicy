package cidrpolicy

import (
	"fmt"
	"net"
)

// WrapBadCIDR turns a raw parse error into one that carries the ErrBadCIDR
// sentinel, so callers can classify the bad-CIDR failure chain with
// errors.Is(err, ErrBadCIDR) instead of string-matching. The underlying cause
// is preserved via %w so errors.Is(err, cause) keeps working too.
func WrapBadCIDR(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %w", ErrBadCIDR, err)
}

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
