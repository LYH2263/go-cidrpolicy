package cidrpolicy_test

import (
	"os"
	"path/filepath"
	"testing"

	cidrpolicy "github.com/LYH2263/go-cidrpolicy"
)

func TestBug09_RotateClosesOldHitLog(t *testing.T) {
	dir := t.TempDir()
	p1 := filepath.Join(dir, "a.log")
	p2 := filepath.Join(dir, "b.log")
	h, err := cidrpolicy.OpenHitLog(p1)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if err := h.Record("1.1.1.1", "r", cidrpolicy.ActionAllow); err != nil {
		t.Fatal(err)
	}
	if err := h.Rotate(p2); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(p1); err != nil {
		t.Fatalf("locked %v", err)
	}
}
