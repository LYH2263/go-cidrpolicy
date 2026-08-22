package cidrpolicy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func writeRules(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "rules.txt")
	if err := os.WriteFile(p, []byte(body), 0644); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	return p
}

// ReloadContext with a live ctx must swap in the new table.
func TestReloadContextHonorsLiveContext(t *testing.T) {
	p := NewPolicy(ActionDeny)
	path := writeRules(t, "allow1 10.0.0.0/8 allow\n")
	if err := p.ReloadContext(context.Background(), path); err != nil {
		t.Fatalf("ReloadContext: %v", err)
	}
	if got := p.Decide("10.1.2.3"); got != ActionAllow {
		t.Fatalf("after reload, decide=%v want allow", got)
	}
}

// A pre-cancelled ctx must leave the live table untouched.
func TestReloadContextPreCancelledLeavesTableUntouched(t *testing.T) {
	p := NewPolicy(ActionDeny)
	path := writeRules(t, "allow1 10.0.0.0/8 allow\n")
	// Establish a known-good live table first.
	if err := p.ReloadContext(context.Background(), path); err != nil {
		t.Fatalf("seed reload: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // "取消重载" pressed before reload starts

	err := p.ReloadContext(ctx, path)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v want context.Canceled", err)
	}
	// Live table must still be the seed table: 10.x still allows.
	if got := p.Decide("10.1.2.3"); got != ActionAllow {
		t.Fatalf("live table was swapped: decide=%v want allow (untouched)", got)
	}
}

// Build a candidate outside the lock, then cancel while waiting for the lock:
// the live table must not be replaced. We force the race by holding p.mu
// across the file read so runReload blocks on p.mu.Lock() until we cancel.
func TestReloadContextCancelledWhileWaitingForLockLeavesTableUntouched(t *testing.T) {
	p := NewPolicy(ActionDeny)
	path := writeRules(t, "allow1 10.0.0.0/8 allow\n")
	if err := p.ReloadContext(context.Background(), path); err != nil {
		t.Fatalf("seed reload: %v", err)
	}

	// Rewrite the rules file so a non-cancelled reload would flip 10.x to deny.
	path2 := writeRules(t, "deny1 10.0.0.0/8 deny\n")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)

	// Hold the lock so ReloadContext blocks inside p.mu.Lock().
	p.mu.Lock()
	go func() {
		done <- p.ReloadContext(ctx, path2)
	}()
	// Give the goroutine time to read the file and reach p.mu.Lock().
	time.Sleep(50 * time.Millisecond)
	cancel() // cancel while it's blocked on the lock
	time.Sleep(20 * time.Millisecond)
	p.mu.Unlock() // release so it can proceed to the under-lock ctx check

	err := <-done
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v want context.Canceled", err)
	}
	// Live table must remain the seed (allow), not the candidate (deny).
	if got := p.Decide("10.1.2.3"); got != ActionAllow {
		t.Fatalf("live table swapped under cancellation: decide=%v want allow", got)
	}
}

// ReloadContext must not leak a half-built table when parsing fails mid-way:
// the live table stays as it was.
func TestReloadContextParseErrorLeavesTableUntouched(t *testing.T) {
	p := NewPolicy(ActionDeny)
	good := writeRules(t, "allow1 10.0.0.0/8 allow\n")
	if err := p.ReloadContext(context.Background(), good); err != nil {
		t.Fatalf("seed reload: %v", err)
	}
	bad := writeRules(t, "broken line without action\n")
	if err := p.ReloadContext(context.Background(), bad); err == nil {
		t.Fatalf("expected parse error, got nil")
	}
	if got := p.Decide("10.1.2.3"); got != ActionAllow {
		t.Fatalf("live table changed after failed parse: decide=%v want allow", got)
	}
}

// Concurrent ReloadContext + Reload must not corrupt the table: each completed
// reload observes a consistent rule set.
func TestReloadContextConcurrentReloadsConsistent(t *testing.T) {
	p := NewPolicy(ActionDeny)
	path := writeRules(t, "allow1 10.0.0.0/8 allow\n")
	if err := p.ReloadContext(context.Background(), path); err != nil {
		t.Fatalf("seed reload: %v", err)
	}

	const n = 20
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			_ = p.ReloadContext(context.Background(), path)
		}()
	}
	wg.Wait()

	if got := p.Decide("10.1.2.3"); got != ActionAllow {
		t.Fatalf("final decide=%v want allow", got)
	}
}
