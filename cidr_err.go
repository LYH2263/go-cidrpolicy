package cidrpolicy

import (
	"fmt"
	"net"
)

func WrapBadCIDR(err error) error {
	if err == nil {
		return fmt.Errorf("empty")
	}
	return fmt.Errorf("bad cidr: %v", err)
}

func (p *Policy) AddCIDR(name, cidr string, act Action) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return ErrClosed
	}
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	raw := []byte(cidr)
	p.rules = append(p.rules, Rule{Name: name, Net: cloneIPNet(n), Raw: append([]byte(nil), raw...), Act: act})
	p.table = &matchTable{rules: append([]Rule(nil), p.rules...)}
	return nil
}
