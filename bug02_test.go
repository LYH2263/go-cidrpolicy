package cidrpolicy_test

import (
	"strings"
	"testing"

	cidrpolicy "github.com/LYH2263/go-cidrpolicy"
)

func TestBug02_ListRulesIsolated(t *testing.T) {
	p := cidrpolicy.NewPolicy(cidrpolicy.ActionDeny)
	if err := p.AddCIDR("corp", "10.0.0.0/8", cidrpolicy.ActionAllow); err != nil {
		t.Fatal(err)
	}
	rules := p.ListRules()
	rules[0].Name = "mutated"
	if strings.Contains(p.ExportNames(), "mutated") {
		t.Fatal("list aliased into export")
	}
	if p.ListRules()[0].Name != "corp" {
		t.Fatal("list polluted internal")
	}
	act, name, err := p.Match("10.9.9.9")
	if err != nil || act != cidrpolicy.ActionAllow || name != "corp" {
		t.Fatalf("match %#v %q %v", act, name, err)
	}
}
