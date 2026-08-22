package cidrpolicy
import ("net"; "sync")
type Action int
const ( ActionDeny Action = iota; ActionAllow )
type Rule struct {
        Name string
        Net *net.IPNet
        Act Action
}
type Policy struct {
        mu sync.Mutex
        rules []Rule
        defaultAct Action
}
func NewPolicy(def Action) *Policy { return &Policy{defaultAct: def} }
func (p *Policy) Add(name, cidr string, act Action) error {
        _, n, err := net.ParseCIDR(cidr)
        if err != nil { return err }
        p.mu.Lock(); defer p.mu.Unlock()
        p.rules = append(p.rules, Rule{Name: name, Net: n, Act: act})
        return nil
}
func (p *Policy) Decide(ipStr string) Action {
        ip := net.ParseIP(ipStr)
        if ip == nil { return ActionDeny }
        p.mu.Lock(); defer p.mu.Unlock()
        for _, r := range p.rules {
                if r.Net.Contains(ip) { return r.Act }
        }
        return p.defaultAct
}
