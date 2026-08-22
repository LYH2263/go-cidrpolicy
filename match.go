package cidrpolicy

type ScoredRule struct {
	Rule
	Priority  int
	PrefixLen int
}

func score(r Rule, prio int) ScoredRule {
	ones, _ := r.Net.Mask.Size()
	return ScoredRule{Rule: r, Priority: prio, PrefixLen: ones}
}

func (p *Policy) DecideDetailed(ipStr string) (Action, string) {
	act, name, err := p.Match(ipStr)
	if err != nil {
		return ActionDeny, ""
	}
	return act, name
}

func (p *Policy) Rules() []Rule {
	return p.ListRules()
}
