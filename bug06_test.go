package cidrpolicy_test

import (
	"os"
	"path/filepath"
	"testing"

	cidrpolicy "github.com/LYH2263/go-cidrpolicy"
)

func TestBug06_ReloadRollback(t *testing.T) {
	p := cidrpolicy.NewPolicy(cidrpolicy.ActionDeny)
	if err := p.AddCIDR("corp", "10.0.0.0/8", cidrpolicy.ActionAllow); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "rules.txt")
	body := "ok 192.168.0.0/16 allow\nbad not-cidr allow\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := p.Reload(path); err == nil {
		t.Fatal("want reload fail")
	}
	act, name, err := p.Match("10.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	if act != cidrpolicy.ActionAllow || name != "corp" {
		t.Fatalf("rolled away %#v %q", act, name)
	}
}
