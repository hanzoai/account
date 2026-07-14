// Copyright 2026 Hanzo AI Inc. All Rights Reserved.

package account

import (
	"os"
	"testing"
)

func TestOf(t *testing.T) {
	os.Setenv("PERSONAL_BILLING_ORGS", "hanzo")
	reset()

	cases := []struct{ org, user, want string }{
		{"hanzo", "alice", "hanzo/alice"}, // personal org → per-user
		{"hanzo", "", "hanzo"},            // personal org, no user (service key) → pool
		{"acme", "bob", "acme"},           // pooled org → the org
		{"acme", "", "acme"},              // pooled org, no user → the org
		{"", "x", ""},                     // no org → cannot bill
		{"HANZO", "Alice", "hanzo/alice"}, // folded
		{"hanzo", "hanzo/alice", "hanzo/alice"}, // already qualified → not double-prefixed
	}
	for _, c := range cases {
		if got := Of(c.org, c.user); got != c.want {
			t.Errorf("Of(%q,%q) = %q, want %q", c.org, c.user, got, c.want)
		}
	}
}

func TestOfKind(t *testing.T) {
	os.Setenv("PERSONAL_BILLING_ORGS", "hanzo")
	reset()
	// A machine principal always pays from the pool, never a per-app account.
	if got := OfKind("hanzo", "svc-bot", true); got != "hanzo" {
		t.Errorf("machine OfKind = %q, want hanzo (pool)", got)
	}
	// A human on a personal org holds their own account.
	if got := OfKind("hanzo", "alice", false); got != "hanzo/alice" {
		t.Errorf("human OfKind = %q, want hanzo/alice", got)
	}
}

func TestOfKey(t *testing.T) {
	os.Setenv("PERSONAL_BILLING_ORGS", "hanzo")
	reset()
	// Composite key with org derived from the prefix.
	if got := OfKey("", "hanzo/alice"); got != "hanzo/alice" {
		t.Errorf("OfKey(,hanzo/alice) = %q, want hanzo/alice", got)
	}
	// Bare key (no slash) is the org.
	if got := OfKey("", "acme"); got != "acme" {
		t.Errorf("OfKey(,acme) = %q, want acme", got)
	}
}

func TestPersonal(t *testing.T) {
	os.Setenv("PERSONAL_BILLING_ORGS", "hanzo,zoo")
	reset()
	for org, want := range map[string]bool{"hanzo": true, "zoo": true, "acme": false, "HANZO": true} {
		if got := Personal(org); got != want {
			t.Errorf("Personal(%q) = %v, want %v", org, got, want)
		}
	}
}

func TestDefaultPersonalIsHanzo(t *testing.T) {
	os.Unsetenv("PERSONAL_BILLING_ORGS")
	reset()
	if !Personal("hanzo") {
		t.Error("default: hanzo must be a personal org")
	}
	if Personal("acme") {
		t.Error("default: acme must be pooled")
	}
}
