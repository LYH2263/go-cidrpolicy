package cidrpolicy

import (
	"errors"
	"strings"
	"testing"
)

// TestBadCIDRFailuresAreSentinelMatchable guards the bug where a corrupted
// CIDR surfaced through Add/AddRule/Reload as either a bare net.ParseCIDR
// error or a %v-flattened string, so errors.Is(err, ErrBadCIDR) never matched
// and the alert panel fell back to string-scanning "cidr" -> all unknown.
func TestBadCIDRFailuresAreSentinelMatchable(t *testing.T) {
	t.Parallel()
	const bad = "10.0.0.256/32" // invalid host bits -> ParseCIDR fails

	t.Run("AddCIDR/Add", func(t *testing.T) {
		p := NewPolicy(ActionDeny)
		for _, err := range []error{
			p.AddCIDR("r", bad, ActionAllow),
			p.Add("r", bad, ActionAllow),
		} {
			if err == nil {
				t.Fatalf("expected error for bad cidr, got nil")
			}
			if !errors.Is(err, ErrBadCIDR) {
				t.Errorf("errors.Is(err, ErrBadCIDR) = false; err=%v", err)
			}
			// offending input must still be surfaced for on-call debugging
			if !strings.Contains(err.Error(), bad) {
				t.Errorf("error message lost the bad cidr text; err=%v", err)
			}
		}
	})

	t.Run("AddRule", func(t *testing.T) {
		p := NewPolicy(ActionDeny)
		err := p.AddRule("r", []byte(bad), ActionAllow)
		if err == nil {
			t.Fatalf("expected error for bad cidr, got nil")
		}
		if !errors.Is(err, ErrBadCIDR) {
			t.Errorf("errors.Is(err, ErrBadCIDR) = false; err=%v", err)
		}
	})

	t.Run("parseRuleLines/Reload", func(t *testing.T) {
		// invalid cidr mid-file; parseRuleLines must surface ErrBadCIDR.
		_, err := parseRuleLines("good 10.0.0.0/8 allow\nbad " + bad + " allow\n")
		if err == nil {
			t.Fatalf("expected error for bad cidr, got nil")
		}
		if !errors.Is(err, ErrBadCIDR) {
			t.Errorf("errors.Is(err, ErrBadCIDR) = false; err=%v", err)
		}
	})

	t.Run("nil input is not bad cidr", func(t *testing.T) {
		if err := WrapBadCIDR(nil); err != nil {
			t.Errorf("WrapBadCIDR(nil) = %v, want nil", err)
		}
	})
}
