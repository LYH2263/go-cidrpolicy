package cidrpolicy

import "testing"

// TestListRulesDoesNotPolluteLiveRuleset reproduces the reported bug:
// the firewall console mutates a returned rule's Name as a filter label,
// which must NOT leak into ExportNames or any subsequent Decide.
func TestListRulesDoesNotPolluteLiveRuleset(t *testing.T) {
	p := NewPolicy(ActionDeny)
	if err := p.AddCIDR("trusted-dc", "10.0.0.0/8", ActionAllow); err != nil {
		t.Fatalf("AddCIDR: %v", err)
	}
	if err := p.AddCIDR("vpn", "192.168.0.0/16", ActionAllow); err != nil {
		t.Fatalf("AddCIDR: %v", err)
	}

	before := p.ExportNames()

	// Frontend takes the listing and rewrites a Name as a temporary filter label.
	out := p.ListRules()
	out[0].Name = "FILTER_TMP"

	// 1. ExportNames must reflect the live ruleset, untouched by the display hack.
	if got := p.ExportNames(); got != before {
		t.Fatalf("ExportNames polluted by ListRules mutation: got %q want %q", got, before)
	}

	// 2. Decide must read the true rule name, not the filter label.
	if _, name, err := p.Match("10.1.2.3"); err != nil || name != "trusted-dc" {
		t.Fatalf("Decide read dirty name: name=%q err=%v (want trusted-dc)", name, err)
	}

	// 3. Mutating the returned slice must not change p.rules or p.table backing.
	//    After a table rebuild the true name must still be present.
	if err := p.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if _, name, err := p.Match("10.1.2.3"); err != nil || name != "trusted-dc" {
		t.Fatalf("Decide after Init read dirty name: name=%q err=%v", name, err)
	}
}

// TestListRulesIsIsolatedCopy confirms the returned slice shares no backing
// storage with the internal ruleset across both Name and Raw.
func TestListRulesIsIsolatedCopy(t *testing.T) {
	p := NewPolicy(ActionDeny)
	if err := p.AddCIDR("r1", "172.16.0.0/12", ActionAllow); err != nil {
		t.Fatalf("AddCIDR: %v", err)
	}

	out := p.ListRules()
	out[0].Name = "dirty"
	out[0].Raw[0] = 'X'

	again := p.ListRules()
	if again[0].Name != "r1" {
		t.Fatalf("Name aliased internal state: got %q want r1", again[0].Name)
	}
	if string(again[0].Raw) != "172.16.0.0/12" {
		t.Fatalf("Raw aliased internal state: got %q want 172.16.0.0/12", again[0].Raw)
	}
}
