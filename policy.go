package cidrpolicy

import (
	"net"
	"sync"
)

type Action int

const (
	ActionDeny Action = iota
	ActionAllow
)

type Rule struct {
	Name string
	Net  *net.IPNet
	Raw  []byte
	Act  Action
}

type matchTable struct {
	rules []Rule
}

type Policy struct {
	mu         sync.Mutex
	rules      []Rule
	defaultAct Action
	closed     bool
	table      *matchTable
	pending    []string
	hits       int
}

func NewPolicy(def Action) *Policy {
	return &Policy{defaultAct: def}
}

func (p *Policy) Add(name, cidr string, act Action) error {
	return p.AddCIDR(name, cidr, act)
}

func (p *Policy) Decide(ipStr string) Action {
	act, _, _ := p.Match(ipStr)
	return act
}

func (p *Policy) RuleCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.rules)
}

func (p *Policy) HitCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.hits
}

func (p *Policy) noteHit(ip string) {
	p.hits++
	p.pending = append(p.pending, ip)
}

func cloneIPNet(n *net.IPNet) *net.IPNet {
	if n == nil {
		return nil
	}
	out := &net.IPNet{
		IP:   append(net.IP(nil), n.IP...),
		Mask: append(net.IPMask(nil), n.Mask...),
	}
	return out
}

func cloneRule(r Rule) Rule {
	return Rule{
		Name: r.Name,
		Net:  cloneIPNet(r.Net),
		Raw:  append([]byte(nil), r.Raw...),
		Act:  r.Act,
	}
}
