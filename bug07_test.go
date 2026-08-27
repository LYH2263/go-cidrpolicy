package cidrpolicy_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	cidrpolicy "github.com/LYH2263/go-cidrpolicy"
)

func TestBug07_ReloadContextHonorsCancel(t *testing.T) {
	p := cidrpolicy.NewPolicy(cidrpolicy.ActionDeny)
	_ = p.AddCIDR("corp", "10.0.0.0/8", cidrpolicy.ActionAllow)
	path := filepath.Join(t.TempDir(), "rules.txt")
	if err := os.WriteFile(path, []byte("new 192.168.0.0/16 allow\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := p.ReloadContext(ctx, path); err == nil {
		t.Fatal("want cancel")
	}
	act, name, err := p.Match("10.1.1.1")
	if err != nil || act != cidrpolicy.ActionAllow || name != "corp" {
		t.Fatalf("changed under cancel %#v %q %v", act, name, err)
	}
}
