package cidrpolicy

import (
	"os"
	"path/filepath"
	"testing"
)

// rotateReleasesOldHandle verifies that after Rotate completes, the old hit
// log path is no longer held open by this process. On Windows an open write
// handle lacks FILE_SHARE_DELETE, so a leaked handle surfaces as
// Remove-Item SharingViolation during log rotation cleanup. The rotated
// directory must be deletable once rotation is done.
func TestRotateReleasesOldHandle(t *testing.T) {
	dir := t.TempDir()
	oldPath := filepath.Join(dir, "hits-old.log")
	newPath := filepath.Join(dir, "hits-new.log")

	h, err := OpenHitLog(oldPath)
	if err != nil {
		t.Fatalf("OpenHitLog: %v", err)
	}
	t.Cleanup(func() { _ = h.Close() })
	if err := h.Record("10.0.0.1", "rule-a", ActionDeny); err != nil {
		t.Fatalf("Record: %v", err)
	}

	if err := h.Rotate(newPath); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	// New path must be writable and the logger must keep working.
	if err := h.Record("10.0.0.2", "rule-b", ActionAllow); err != nil {
		t.Fatalf("Record after rotate: %v", err)
	}

	// The defining check: the old rotated file must be removable now that the
	// old handle has been closed, even on Windows. This is what the ops
	// rotation cleanup relies on.
	if err := os.Remove(oldPath); err != nil {
		t.Fatalf("old path still held after Rotate: %v", err)
	}
}

// rotateFailureKeepsOldHandle ensures a failed Rotate does not drop the
// existing handle: logging against the old path must keep working.
func TestRotateFailureKeepsOldHandle(t *testing.T) {
	dir := t.TempDir()
	oldPath := filepath.Join(dir, "hits.log")

	h, err := OpenHitLog(oldPath)
	if err != nil {
		t.Fatalf("OpenHitLog: %v", err)
	}
	t.Cleanup(func() { _ = h.Close() })
	if err := h.Record("10.0.0.1", "rule-a", ActionDeny); err != nil {
		t.Fatalf("Record: %v", err)
	}

	// Point Rotate at a path whose parent does not exist -> OpenFile fails.
	badPath := filepath.Join(dir, "no-such-dir", "hits-new.log")
	if err := h.Rotate(badPath); err == nil {
		t.Fatal("Rotate to missing dir unexpectedly succeeded")
	}

	// Old handle must still be usable.
	if err := h.Record("10.0.0.2", "rule-b", ActionAllow); err != nil {
		t.Fatalf("Record after failed rotate: %v", err)
	}
}
