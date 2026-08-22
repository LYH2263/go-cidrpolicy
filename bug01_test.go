package cidrpolicy_test

import (
	"bytes"
	"testing"

	cidrpolicy "github.com/LYH2263/go-cidrpolicy"
)

func TestBug01_AddRuleIsolatesCIDR(t *testing.T) {
	p := cidrpolicy.NewPolicy(cidrpolicy.ActionDeny)
	buf := []byte("10.0.0.0/8")
	if err := p.AddRule("corp", buf, cidrpolicy.ActionAllow); err != nil {
		t.Fatal(err)
	}
	buf[0] = '9'
	act, _, err := p.Match("10.1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	if act != cidrpolicy.ActionAllow {
		t.Fatalf("addrule leaked act=%v", act)
	}
	snap := p.SnapshotRaws()
	if len(snap) == 0 {
		t.Fatal("empty snap")
	}
	snap[0][0] = 'Z'
	got := p.SnapshotRaws()
	if bytes.Equal(got[0], snap[0]) {
		t.Fatal("snapshot leaked")
	}
}
