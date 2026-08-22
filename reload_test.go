package cidrpolicy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// writeFile is a small helper for emitting a rule file used by Reload.
func writeFile(t *testing.T, name, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

// TestReloadPartialParseLeavesSnapshotIntact is the regression test for the
// hot-reload half-update incident: a config with one valid rule followed by
// a malformed line must return an error AND leave the previously loaded rule
// set untouched, so traffic still resolves against the pre-reload snapshot.
func TestReloadPartialParseLeavesSnapshotIntact(t *testing.T) {
	p := NewPolicy(ActionDeny)
	// Seed an initial, working rule set that allows 10.0.0.0/8.
	good := writeFile(t, "good.txt",
		"lan 10.0.0.0/8 allow\n")
	if err := p.Reload(good); err != nil {
		t.Fatalf("initial reload: %v", err)
	}
	if act := p.Decide("10.0.0.5"); act != ActionAllow {
		t.Fatalf("10.0.0.0/8 should be allowed before bad reload, got %v", act)
	}
	before := p.ExportNames() // "lan"
	beforeCount := p.RuleCount()

	// Reload a config whose second line is malformed. parseRuleLines
	// returns the one good rule it parsed plus the error; the bug was to
	// commit that partial slice.
	bad := writeFile(t, "bad.txt",
		"lan 10.0.0.0/8 allow\nbad-line-not-three-fields\n")
	err := p.Reload(bad)
	if err == nil {
		t.Fatalf("expected parse error from malformed config, got nil")
	}

	// The live rule set must be byte-for-byte the pre-reload snapshot.
	if got := p.ExportNames(); got != before {
		t.Fatalf("rule names changed after failed reload: got %q want %q", got, before)
	}
	if got := p.RuleCount(); got != beforeCount {
		t.Fatalf("rule count changed after failed reload: got %d want %d", got, beforeCount)
	}
	// 10.0.0.5 must still match the seeded allow rule, not fall through to
	// the deny default — this is exactly the "previously allowed segment
	// suddenly denied" failure mode that hit production.
	if act := p.Decide("10.0.0.5"); act != ActionAllow {
		t.Fatalf("10.0.0.5 denied after failed reload; snapshot not preserved, got %v", act)
	}
}

// TestReloadBadActionLeavesSnapshotIntact covers the other parse-failure branch
// (a bogus action verb) with a slightly different seeded table to ensure the
// snapshot invariant holds regardless of which line fails parsing.
func TestReloadBadActionLeavesSnapshotIntact(t *testing.T) {
	p := NewPolicy(ActionDeny)
	good := writeFile(t, "good.txt",
		"corp 172.16.0.0/12 allow\nwan 0.0.0.0/0 deny\n")
	if err := p.Reload(good); err != nil {
		t.Fatalf("initial reload: %v", err)
	}
	if act := p.Decide("172.16.5.5"); act != ActionAllow {
		t.Fatalf("172.16.0.0/12 should be allowed, got %v", act)
	}
	beforeNames := p.ExportNames()
	beforeCount := p.RuleCount()

	bad := writeFile(t, "bad.txt",
		"corp 172.16.0.0/12 allow\nbogus 1.2.3.4/32 maybe\n")
	if err := p.Reload(bad); err == nil {
		t.Fatalf("expected parse error from bad action, got nil")
	}
	if got := p.ExportNames(); got != beforeNames {
		t.Fatalf("rule names changed after failed reload: got %q want %q", got, beforeNames)
	}
	if got := p.RuleCount(); got != beforeCount {
		t.Fatalf("rule count changed after failed reload: got %d want %d", got, beforeCount)
	}
	if act := p.Decide("172.16.5.5"); act != ActionAllow {
		t.Fatalf("172.16.5.5 denied after failed reload; snapshot not preserved, got %v", act)
	}
}

// TestReloadSuccessReplacesSnapshot confirms the happy path still swaps the
// table in full, so the fix did not regress a legitimate reload.
func TestReloadSuccessReplacesSnapshot(t *testing.T) {
	p := NewPolicy(ActionDeny)
	first := writeFile(t, "first.txt", "a 10.0.0.0/8 allow\n")
	if err := p.Reload(first); err != nil {
		t.Fatalf("first reload: %v", err)
	}
	second := writeFile(t, "second.txt", "b 192.168.0.0/16 allow\n")
	if err := p.Reload(second); err != nil {
		t.Fatalf("second reload: %v", err)
	}
	if act := p.Decide("10.0.0.5"); act != ActionDeny {
		t.Fatalf("old rule 10.0.0.0/8 should be gone after successful reload, got %v", act)
	}
	if act := p.Decide("192.168.1.1"); act != ActionAllow {
		t.Fatalf("new rule 192.168.0.0/16 should be allowed after successful reload, got %v", act)
	}
	if got := p.ExportNames(); got != "b" {
		t.Fatalf("names after reload: got %q want %q", got, "b")
	}
}

// TestReloadBadCIDRLeavesSnapshotIntact covers a malformed CIDR mid-file,
// the concrete trigger from the incident (a deliberately injected bad rule).
func TestReloadBadCIDRLeavesSnapshotIntact(t *testing.T) {
	p := NewPolicy(ActionDeny)
	good := writeFile(t, "good.txt", "lan 10.0.0.0/8 allow\n")
	if err := p.Reload(good); err != nil {
		t.Fatalf("initial reload: %v", err)
	}
	before := p.ExportNames()
	beforeCount := p.RuleCount()

	bad := writeFile(t, "bad.txt",
		"lan 10.0.0.0/8 allow\njunk 999.0.0.0/8 allow\n")
	err := p.Reload(bad)
	if err == nil {
		t.Fatalf("expected parse error from bad CIDR, got nil")
	}
	if !errors.Is(err, ErrBadCIDR) {
		t.Fatalf("expected ErrBadCIDR sentinel, got %v", err)
	}
	if got := p.ExportNames(); got != before {
		t.Fatalf("rule names changed after failed reload: got %q want %q", got, before)
	}
	if got := p.RuleCount(); got != beforeCount {
		t.Fatalf("rule count changed after failed reload: got %d want %d", got, beforeCount)
	}
	if act := p.Decide("10.0.0.5"); act != ActionAllow {
		t.Fatalf("10.0.0.5 denied after failed reload; snapshot not preserved, got %v", act)
	}
}

// TestReloadContextCanceledLeavesSnapshotIntact verifies that a context
// cancelled before the file is read never mutates the live table.
func TestReloadContextCanceledLeavesSnapshotIntact(t *testing.T) {
	p := NewPolicy(ActionDeny)
	good := writeFile(t, "good.txt", "lan 10.0.0.0/8 allow\n")
	if err := p.Reload(good); err != nil {
		t.Fatalf("initial reload: %v", err)
	}
	before := p.ExportNames()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel up front
	bad := writeFile(t, "bad.txt", "lan 10.0.0.0/8 allow\nbroken\n")
	if err := p.ReloadContext(ctx, bad); err == nil {
		t.Fatalf("expected cancellation error, got nil")
	}
	if got := p.ExportNames(); got != before {
		t.Fatalf("rule names changed after cancelled reload: got %q want %q", got, before)
	}
	if act := p.Decide("10.0.0.5"); act != ActionAllow {
		t.Fatalf("10.0.0.5 denied after cancelled reload; snapshot not preserved, got %v", act)
	}
}
