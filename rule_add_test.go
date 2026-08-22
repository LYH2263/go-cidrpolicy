package cidrpolicy

import "testing"

// TestAddRule_BufferReuseNoAlias guards against the caller reusing a single CIDR
// byte buffer across batched AddRule calls. The stored rule's Raw must be an
// independent copy; otherwise later overwrites drift the already-registered rule
// and (because ruleNet prefers Raw over Net) corrupt Match results.
func TestAddRule_BufferReuseNoAlias(t *testing.T) {
	p := NewPolicy(ActionAllow)

	// Caller reuses one buffer for each prefix, as a batch loader might.
	buf := []byte("10.0.0.0/24")
	if err := p.AddRule("a", buf, ActionDeny); err != nil {
		t.Fatalf("AddRule a: %v", err)
	}

	// Simulate the caller mutating the shared buffer for the next prefix.
	copy(buf, "10.0.1.0/24")

	// Already-registered rule "a" must still match 10.0.0.5, not drift to 10.0.1.0/24.
	if act, name, _ := p.Match("10.0.0.5"); act != ActionDeny || name != "a" {
		t.Fatalf("drifted match after buffer reuse: act=%v name=%q (want Deny/a)", act, name)
	}
	if act, _, _ := p.Match("10.0.1.5"); act != ActionAllow {
		t.Fatalf("10.0.1.5 should not match rule a, got act=%v", act)
	}

	// SnapshotRaws must be independent of both the caller's buffer and internal state.
	shot := p.SnapshotRaws()
	if len(shot) != 1 || string(shot[0]) != "10.0.0.0/24" {
		t.Fatalf("SnapshotRaws = %q, want [10.0.0.0/24]", shot)
	}
	// Mutating the exported snapshot must not corrupt the stored rule.
	shot[0][0] = 'X'
	if _, _, err := p.Match("10.0.0.5"); err != nil {
		t.Fatalf("match after mutating snapshot broke internal state: %v", err)
	}
}

// TestAddRule_Sequence asserts a realistic batch of prefixes lands in order,
// each matching exactly its own range — the graylist integrity check.
func TestAddRule_Sequence(t *testing.T) {
	p := NewPolicy(ActionAllow)
	prefixes := []string{"10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24"}
	for i, px := range prefixes {
		buf := append([]byte(nil), px...) // independent buffers, like a real loader
		if err := p.AddRule(string(rune('a'+i)), buf, ActionDeny); err != nil {
			t.Fatalf("AddRule %d: %v", i, err)
		}
	}
	hostIPs := []string{"10.0.0.5", "10.0.1.5", "10.0.2.5"}
	for i, want := range string("abc") {
		if act, name, _ := p.Match(hostIPs[i]); act != ActionDeny || name != string(want) {
			t.Fatalf("Match(%s) = act=%v name=%q, want Deny/%c", hostIPs[i], act, name, want)
		}
	}
}
