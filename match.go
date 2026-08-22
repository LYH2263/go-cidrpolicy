package cidrpolicy
import (
        "net"
        "sort"
)
type ScoredRule struct {
        Rule
        Priority int
        PrefixLen int
}
func score(r Rule, prio int) ScoredRule {
        ones, _ := r.Net.Mask.Size()
        return ScoredRule{Rule: r, Priority: prio, PrefixLen: ones}
}
func (p *Policy) DecideDetailed(ipStr string) (Action, string) {
        ip := net.ParseIP(ipStr)
        if ip == nil { return ActionDeny, "" }
        p.mu.Lock(); defer p.mu.Unlock()
        hits := make([]ScoredRule, 0)
        for i, r := range p.rules {
                if r.Net.Contains(ip) {
                        hits = append(hits, score(r, i))
                }
        }
        if len(hits) == 0 { return p.defaultAct, "" }
        sort.SliceStable(hits, func(i, j int) bool {
                if hits[i].PrefixLen != hits[j].PrefixLen {
                        return hits[i].PrefixLen > hits[j].PrefixLen
                }
                return hits[i].Priority < hits[j].Priority
        })
        return hits[0].Act, hits[0].Name
}
func (p *Policy) Rules() []Rule {
        p.mu.Lock(); defer p.mu.Unlock()
        out := make([]Rule, len(p.rules))
        copy(out, p.rules)
        return out
}
