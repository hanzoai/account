// Copyright 2026 Hanzo AI Inc. All Rights Reserved.

// Package account resolves who a request pays as — the billing account, the
// wallet money lands in and the gate reads out of. It is the ONE rule, shared by
// every serving layer (ai, commerce, cloud), so a customer can never top up one
// account and spend from another.
//
// The account is derived from two facts — the org and the user — by one function,
// Of. The default is per-org (a company pays for what its members spend); an org
// on the Personal set instead holds a per-user account (a person has their own
// wallet). This is policy, read from the environment once, so the rule lives in
// data, not scattered branches.
package account

import (
	"os"
	"strings"
	"sync"
)

// Of returns the billing account for (org, user) — the value passed to the gate
// and the ledger:
//
//	pooled org      → "org"        (a company; members share one account)
//	personal org    → "org/user"   (a person holds their own account)
//	org-only caller → "org"        (a service key has no user; it pays from the pool)
//
// Empty org yields "" (the caller cannot bill — fail closed). An already-qualified
// "org/user" is never double-prefixed, so a resolved account round-trips.
func Of(org, user string) string {
	org = fold(org)
	if org == "" {
		return ""
	}
	if !Personal(org) {
		return org
	}
	user = fold(user)
	if user == "" {
		return org
	}
	if strings.HasPrefix(user, org+"/") {
		return user
	}
	return org + "/" + user
}

// OfKind is Of for an authenticated caller, accounting for machine identities. A
// machine (client-credentials / application) principal has no funded per-user
// account, so it always pays from the org pool — billing it "org/app" would 402
// legitimate service traffic. `machine` is true for a non-human principal.
func OfKind(org, user string, machine bool) string {
	if machine {
		return Of(org, "")
	}
	return Of(org, user)
}

// OfKey is Of for a caller that already holds the "org/user" composite as one
// string (a usage record, a resolved key). org may be empty — it is then taken
// from the key's prefix.
func OfKey(org, key string) string {
	user := ""
	if i := strings.IndexByte(key, '/'); i >= 0 {
		if fold(org) == "" {
			org = key[:i]
		}
		user = key[i+1:]
	} else if fold(org) == "" {
		org = key
	}
	return Of(org, user)
}

// Personal reports whether an org holds per-user accounts rather than one pooled
// account. It is the ONE switch between the two billing shapes.
func Personal(org string) bool {
	_, ok := personalSet()[fold(org)]
	return ok
}

func fold(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// personalSet is the org set that holds per-user accounts, parsed once from
// PERSONAL_BILLING_ORGS (default "hanzo" — the shared catch-all org, where each
// signup is a person with their own wallet). A real company org is pooled.
var (
	personalOnce sync.Once
	personal     map[string]struct{}
)

func personalSet() map[string]struct{} {
	personalOnce.Do(func() {
		raw := strings.TrimSpace(os.Getenv("PERSONAL_BILLING_ORGS"))
		if raw == "" {
			raw = "hanzo"
		}
		personal = parse(raw)
	})
	return personal
}

func parse(raw string) map[string]struct{} {
	m := map[string]struct{}{}
	for _, o := range strings.Split(raw, ",") {
		if o = fold(o); o != "" {
			m[o] = struct{}{}
		}
	}
	return m
}

// reset re-reads the environment; for tests that set PERSONAL_BILLING_ORGS after
// first use (the sync.Once would otherwise serve a stale set).
func reset() {
	personalOnce = sync.Once{}
	personal = nil
}
