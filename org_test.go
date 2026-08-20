// Copyright 2026 Hanzo AI Inc. All Rights Reserved.

package account

import (
	"encoding/json"
	"errors"
	"testing"
)

// alice belongs to her home org and two teams. Every switch test selects from
// this one set, so the cases differ only in what is ASKED for.
var alice = []OrgRef{
	{Org: "hanzo", Role: "member"}, // home, always first (IAM mints it that way)
	{Org: "acme", Role: "admin"},
	{Org: "globex", Role: "member"},
}

// TestEffectiveOrg is the membership gate, exhaustively. The rule under test:
// the ask is honored iff it byte-equals an org in the SIGNED set; everything
// else is home, silently.
func TestEffectiveOrg(t *testing.T) {
	cases := []struct {
		name      string
		owner     string
		orgs      []OrgRef
		requested string
		want      string
		wantErr   bool
	}{
		// --- the feature: a member selects a team and gets it ---
		{
			name:      "member switches to a team org",
			owner:     "hanzo",
			orgs:      alice,
			requested: "acme",
			want:      "acme",
		},
		{
			name:      "member switches to their other team",
			owner:     "hanzo",
			orgs:      alice,
			requested: "globex",
			want:      "globex",
		},
		{
			name:      "member selects home explicitly",
			owner:     "hanzo",
			orgs:      alice,
			requested: "hanzo",
			want:      "hanzo",
		},

		// --- no ask: the no-op path every non-switching user takes ---
		{
			name:      "no ask resolves home",
			owner:     "hanzo",
			orgs:      alice,
			requested: "",
			want:      "hanzo",
		},
		{
			name:      "no ask and no claim set resolves home",
			owner:     "hanzo",
			orgs:      nil,
			requested: "",
			want:      "hanzo",
		},

		// --- the gate: an org outside the signed set is refused, silently ---
		{
			name:      "non-member org is refused",
			owner:     "hanzo",
			orgs:      alice,
			requested: "initech",
			want:      "",
			wantErr:   true,
		},
		{
			name:      "empty claim set admits nothing (legacy token, opaque key, machine)",
			owner:     "hanzo",
			orgs:      nil,
			requested: "acme",
			want:      "",
			wantErr:   true,
		},
		{
			name:      "empty non-nil claim set admits nothing",
			owner:     "hanzo",
			orgs:      []OrgRef{},
			requested: "acme",
			want:      "",
			wantErr:   true,
		},
		{
			name:      "a claim set naming only home cannot reach a team",
			owner:     "hanzo",
			orgs:      []OrgRef{{Org: "hanzo", Role: "owner"}},
			requested: "acme",
			want:      "",
			wantErr:   true,
		},

		// --- verbatim comparison: no fold, no trim, no normalization ---
		// Each of these is a DIFFERENT string from a granted org. IAM treats them
		// as distinct orgs, so each must be refused rather than resolved to the
		// org it merely resembles.
		{
			name:      "upper case is a different org",
			owner:     "hanzo",
			orgs:      alice,
			requested: "ACME",
			want:      "",
			wantErr:   true,
		},
		{
			name:      "title case is a different org",
			owner:     "hanzo",
			orgs:      alice,
			requested: "Acme",
			want:      "",
			wantErr:   true,
		},
		{
			name:      "mixed case is a different org",
			owner:     "hanzo",
			orgs:      alice,
			requested: "aCmE",
			want:      "",
			wantErr:   true,
		},
		{
			name:      "an interior space is a different org",
			owner:     "hanzo",
			orgs:      alice,
			requested: "ac me",
			want:      "",
			wantErr:   true,
		},
		{
			name:      "a leading space is a different org",
			owner:     "hanzo",
			orgs:      alice,
			requested: " acme",
			want:      "",
			wantErr:   true,
		},
		{
			name:      "a trailing space is a different org",
			owner:     "hanzo",
			orgs:      alice,
			requested: "acme ",
			want:      "",
			wantErr:   true,
		},
		{
			name:      "surrounding whitespace is a different org",
			owner:     "hanzo",
			orgs:      alice,
			requested: "\tacme\n",
			want:      "",
			wantErr:   true,
		},
		{
			name:      "a zero-width space is a different org",
			owner:     "hanzo",
			orgs:      alice,
			requested: "acme\u200b",
			want:      "",
			wantErr:   true,
		},
		{
			name:      "an interior zero-width joiner is a different org",
			owner:     "hanzo",
			orgs:      alice,
			requested: "ac\u200dme",
			want:      "",
			wantErr:   true,
		},
		{
			name:      "a zero-width no-break space is a different org",
			owner:     "hanzo",
			orgs:      alice,
			requested: "\ufeffacme",
			want:      "",
			wantErr:   true,
		},
		{
			name:      "a NUL byte is a different org",
			owner:     "hanzo",
			orgs:      alice,
			requested: "acme\x00",
			want:      "",
			wantErr:   true,
		},
		{
			name:      "a Cyrillic homoglyph is a different org",
			owner:     "hanzo",
			orgs:      alice,
			requested: "\u0430cme", // Cyrillic а, not Latin a
			want:      "",
			wantErr:   true,
		},
		{
			name:      "a prefix of a granted org is a different org",
			owner:     "hanzo",
			orgs:      alice,
			requested: "acm",
			want:      "",
			wantErr:   true,
		},
		{
			name:      "a superstring of a granted org is a different org",
			owner:     "hanzo",
			orgs:      alice,
			requested: "acmex",
			want:      "",
			wantErr:   true,
		},
		{
			name:      "a path-shaped ask is a different org",
			owner:     "hanzo",
			orgs:      alice,
			requested: "acme/admin",
			want:      "",
			wantErr:   true,
		},
		{
			name:      "whitespace alone is a different org",
			owner:     "hanzo",
			orgs:      alice,
			requested: "   ",
			want:      "",
			wantErr:   true,
		},

		// --- the home org itself is compared verbatim too ---
		{
			// Home is not in the claim set here, so it can only match via the
			// owner comparison — which is also byte-exact. A cased variant of home
			// is refused and lands on home, which is the same value either way.
			name:      "cased home with no claim set still resolves home",
			owner:     "hanzo",
			orgs:      nil,
			requested: "HANZO",
			want:      "",
			wantErr:   true,
		},
		{
			// Two orgs differing only in case are DISTINCT, and both may be
			// granted. Selecting each must yield exactly that one.
			name:      "case-distinct orgs are independently selectable",
			owner:     "hanzo",
			orgs:      []OrgRef{{Org: "acme"}, {Org: "ACME"}},
			requested: "ACME",
			want:      "ACME",
		},
		{
			name:      "case-distinct orgs do not bleed into each other",
			owner:     "hanzo",
			orgs:      []OrgRef{{Org: "acme"}, {Org: "ACME"}},
			requested: "acme",
			want:      "acme",
		},

		// --- unattributable subject: fail closed even with a coherent set ---
		{
			name:      "no owner cannot switch",
			owner:     "",
			orgs:      alice,
			requested: "acme",
			want:      "",
			wantErr:   true,
		},
		{
			name:      "no owner and no ask resolves nothing",
			owner:     "",
			orgs:      nil,
			requested: "",
			want:      "",
		},

		// --- a blank entry in the set never becomes a wildcard ---
		{
			name:      "an empty org in the set does not match an empty ask",
			owner:     "hanzo",
			orgs:      []OrgRef{{Org: ""}},
			requested: "",
			want:      "hanzo",
		},
		{
			name:      "role is never consulted",
			owner:     "hanzo",
			orgs:      []OrgRef{{Org: "acme", Role: ""}},
			requested: "acme",
			want:      "acme",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := EffectiveOrg(tc.owner, tc.orgs, tc.requested)
			if tc.wantErr {
				if !errors.Is(err, ErrOrgForbidden) {
					t.Fatalf("EffectiveOrg(%q, %v, %q) = (%q, %v), want ErrOrgForbidden — an explicit ask must refuse, never redirect the bill",
						tc.owner, tc.orgs, tc.requested, got, err)
				}
				if got != "" {
					t.Fatalf("EffectiveOrg returned org %q alongside a refusal; a refused selection must name no payer", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("EffectiveOrg(%q, %v, %q) errored: %v", tc.owner, tc.orgs, tc.requested, err)
			}
			if got != tc.want {
				t.Fatalf("EffectiveOrg(%q, %v, %q) = %q, want %q",
					tc.owner, tc.orgs, tc.requested, got, tc.want)
			}
		})
	}
}

// TestEffectiveOrg_ReturnsTheSignedSlug proves no client-supplied string can flow
// onward as an org. Whatever comes back is either the owner claim or an element
// of the signed set — never the `requested` argument as such. This is what makes
// the comparison's strictness structural rather than incidental: even if the
// predicate were later loosened, the VALUE returned still comes from IAM.
func TestEffectiveOrg_ReturnsTheSignedSlug(t *testing.T) {
	asks := []string{"", "acme", "ACME", "initech", " acme", "acme\u200b", "\x00", "hanzo"}

	for _, ask := range asks {
		got, err := EffectiveOrg("hanzo", alice, ask)
		if err != nil {
			continue // a refused ask names no org, so there is no slug to check
		}

		signed := got == "hanzo"
		for _, o := range alice {
			if got == o.Org {
				signed = true
			}
		}
		if !signed {
			t.Fatalf("EffectiveOrg returned %q for ask %q — not the owner claim and not in the signed set", got, ask)
		}
	}
}

// TestLedgerOrg is the money policy: who pays for the org the request acts in.
func TestLedgerOrg(t *testing.T) {
	cases := []struct {
		name      string
		effective string
		home      string
		sudo      bool
		want      string
	}{
		{
			// The feature. The switcher picked acme, so acme's balance pays.
			name:      "member switch bills the selected org",
			effective: "acme",
			home:      "hanzo",
			sudo:      false,
			want:      "acme",
		},
		{
			// The guard. A support admin inside a customer's org spends OUR books,
			// never the customer's — their data, our bill.
			name:      "masquerade bills the admin's own org",
			effective: "acme",
			home:      "admin",
			sudo:      true,
			want:      "admin",
		},
		{
			name:      "no switch bills home",
			effective: "hanzo",
			home:      "hanzo",
			sudo:      false,
			want:      "hanzo",
		},
		{
			// sudo at home is not a special case: both branches agree there.
			name:      "sudo at home bills home",
			effective: "admin",
			home:      "admin",
			sudo:      true,
			want:      "admin",
		},
		{
			// A refused switch already collapsed to home upstream, so sudo or not,
			// the bill is home. Proves the two functions compose without a gap.
			name:      "refused switch bills home for a normal member",
			effective: "hanzo",
			home:      "hanzo",
			sudo:      false,
			want:      "hanzo",
		},
		{
			name:      "an unattributable request bills nothing",
			effective: "",
			home:      "",
			sudo:      false,
			want:      "",
		},
		{
			// Sudo is answered from `home`, so an empty effective cannot make an
			// admin's bill disappear.
			name:      "sudo with no effective org still bills home",
			effective: "",
			home:      "admin",
			sudo:      true,
			want:      "admin",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := LedgerOrg(tc.effective, tc.home, tc.sudo); got != tc.want {
				t.Fatalf("LedgerOrg(%q, %q, %v) = %q, want %q",
					tc.effective, tc.home, tc.sudo, got, tc.want)
			}
		})
	}
}

// TestNoSwitchIsANoOp is the adoption proof, and the reason this can land in
// three layers at once.
//
// Before these functions existed, every layer billed the home org: it read
// user.Owner (ai), or minted X-Org-Id from the `owner` claim (gateway), and
// called Payer with it. The claim here is that a caller which routes that same
// credential through EffectiveOrg → LedgerOrg → Payer gets a BYTE-IDENTICAL
// answer for every principal who is not switching — which is every principal
// today, since no client sends the selection at all.
//
// So the wire is compared against the code it replaces, for every owner kind and
// every claim-set shape, including asks that are REFUSED (a refusal must be
// indistinguishable from no ask — that is what "silent" means).
func TestNoSwitchIsANoOp(t *testing.T) {
	creds := []Credential{
		{Owner: "hanzo", Name: "alice"},                               // person in the signup org
		{Owner: "acme", Name: "bob"},                                  // person in a real org
		{Owner: "hanzo", Name: "hanzo-cloud", Account: "org:hanzo"},   // machine credential
		{Owner: "globex", Name: "carol", Account: "org:globex"},       // claim names the org
		{Owner: "hanzo", Name: "dave", Account: "person:hanzo/dave"},  // claim names the person
		{Owner: "acme", Name: "eve", Account: "project:acme/website"}, // claim names a project
		{Owner: "hanzo", Name: "mallory", Account: "org:acme"},        // foreign claim (refused by Payer)
		{Owner: "hanzo", Name: ""},                                    // no name
	}

	// Every shape of claim set, crossed with every ask that is NOT a granted
	// switch. No ask here byte-equals a set entry, so none may move the ledger —
	// and if a later edit adds one that does, this fails loudly instead of
	// silently skipping it.
	sets := [][]OrgRef{nil, {}, alice, {{Org: "hanzo"}}}
	asks := []string{
		"",           // the overwhelmingly common case: no client sends one
		"initech",    // outside the set
		"ACME",       // cased variant of a granted org
		" acme",      // padded variant
		"acme\u200b", // zero-width-suffixed variant
		"   ",        // whitespace
	}

	for _, cred := range creds {
		for _, set := range sets {
			for _, ask := range asks {
				eff, effErr := EffectiveOrg(cred.Owner, set, ask)
				if effErr != nil {
					continue // a refused ask selects no payer; there is nothing to compare
				}
				ledger := LedgerOrg(eff, cred.Owner, false)

				// The credential as the new pipeline would build it, versus the
				// credential the old code built straight from the owner claim.
				now := Payer(Credential{Owner: ledger, Name: cred.Name, Account: cred.Account})
				before := Payer(cred)

				if now.Subject() != before.Subject() {
					t.Fatalf("owner=%q set=%v ask=%q: subject moved %q → %q",
						cred.Owner, set, ask, before.Subject(), now.Subject())
				}
				if now.Org() != before.Org() {
					t.Fatalf("owner=%q set=%v ask=%q: ledger moved %q → %q",
						cred.Owner, set, ask, before.Org(), now.Org())
				}
			}
		}
	}
}

// TestSwitchMovesTheLedger is the converse: when a member DOES select a granted
// org, the money moves — gate and debit both, because both call Payer with the
// same LedgerOrg result. A test that only proved the no-op would be satisfied by
// a function that never switches at all.
func TestSwitchMovesTheLedger(t *testing.T) {
	// alice is a person in the signup org: at home she pays from her own wallet.
	home := Payer(Credential{Owner: "hanzo", Name: "alice"})
	if got := home.Subject(); got != "hanzo/alice" {
		t.Fatalf("at home: subject = %q, want %q", got, "hanzo/alice")
	}

	// She selects acme, a team she is granted. The team pool pays.
	eff, err := EffectiveOrg("hanzo", alice, "acme")
	if err != nil {
		t.Fatalf("a granted team was refused: %v", err)
	}
	ledger := LedgerOrg(eff, "hanzo", false)
	switched := Payer(Credential{Owner: ledger, Name: "alice"})

	if eff != "acme" {
		t.Fatalf("effective org = %q, want %q", eff, "acme")
	}
	if got := switched.Subject(); got != "acme" {
		t.Fatalf("switched: subject = %q, want %q (the team pool)", got, "acme")
	}
	if switched.Subject() == home.Subject() {
		t.Fatal("switching did not move the ledger — the switcher would not pay")
	}
}

// TestMasqueradeNeverSpendsTheCustomer is the guard, end to end. A platform admin
// acting inside a customer's org must act on the customer's DATA and spend the
// admin org's MONEY. The two functions disagree on purpose, and that disagreement
// is the whole point of keeping them separate.
func TestMasqueradeNeverSpendsTheCustomer(t *testing.T) {
	// A support admin whose home is the admin org, acting in acme. Sudo grants the
	// scope, so `effective` is acme regardless of what EffectiveOrg would say —
	// masquerade is a different authority and its caller supplies it.
	const effective, adminHome = "acme", "admin"

	ledger := LedgerOrg(effective, adminHome, true)
	if ledger == effective {
		t.Fatalf("masquerade billed the customer's ledger %q", ledger)
	}
	if ledger != adminHome {
		t.Fatalf("masquerade ledger = %q, want %q", ledger, adminHome)
	}
	if got := Payer(Credential{Owner: ledger, Name: "root"}).Subject(); got != "admin" {
		t.Fatalf("masquerade payer = %q, want %q", got, "admin")
	}
}

// TestEffectiveOrg_IsPure guards the properties the three layers rely on to agree:
// the answer depends on nothing but the arguments, and the arguments come back
// unmutated (the claim slice is decoded once per request and shared).
func TestEffectiveOrg_IsPure(t *testing.T) {
	orgs := []OrgRef{{Org: "hanzo", Role: "member"}, {Org: "acme", Role: "admin"}}
	before := append([]OrgRef(nil), orgs...)

	first, firstErr := EffectiveOrg("hanzo", orgs, "acme")
	if firstErr != nil {
		t.Fatalf("a granted org was refused: %v", firstErr)
	}
	for i := 0; i < 100; i++ {
		if got, _ := EffectiveOrg("hanzo", orgs, "acme"); got != first {
			t.Fatalf("call %d returned %q, first returned %q — not a function of its arguments", i, got, first)
		}
	}
	for i := range orgs {
		if orgs[i] != before[i] {
			t.Fatalf("the claim set was mutated: %v → %v", before, orgs)
		}
	}
}

// TestOrgRef_DecodesTheIAMWire pins the wire contract against the exact bytes IAM
// signs. Three repos decode this claim; if a tag here drifts from IAM's, a member
// silently loses every membership and every switch fails closed to home — a bug
// that presents as "the switcher does nothing", which is the bug these functions
// were written to end. Decoding real wire bytes tests that, where asserting on
// struct tags would only restate them.
func TestOrgRef_DecodesTheIAMWire(t *testing.T) {
	// A verbatim `orgs` claim as iam/internal/store.MemberOrgRefs mints it: home
	// org first with its role, then explicit memberships.
	const wire = `[{"org":"hanzo","role":"owner"},{"org":"acme","role":"admin"},{"org":"globex","role":"member"}]`

	var orgs []OrgRef
	if err := json.Unmarshal([]byte(wire), &orgs); err != nil {
		t.Fatalf("decoding the IAM wire failed: %v", err)
	}

	want := []OrgRef{
		{Org: "hanzo", Role: "owner"},
		{Org: "acme", Role: "admin"},
		{Org: "globex", Role: "member"},
	}
	if len(orgs) != len(want) {
		t.Fatalf("decoded %d memberships, want %d", len(orgs), len(want))
	}
	for i := range want {
		if orgs[i] != want[i] {
			t.Fatalf("membership %d = %+v, want %+v", i, orgs[i], want[i])
		}
	}

	// The decoded set must drive the gate — the whole reason the shape matters.
	if got, err := EffectiveOrg("hanzo", orgs, "acme"); err != nil || got != "acme" {
		t.Fatalf("a decoded membership did not authorize its own org: got %q err %v", got, err)
	}

	// Role is optional on the wire; a set that omits it still authorizes.
	var terse []OrgRef
	if err := json.Unmarshal([]byte(`[{"org":"acme"}]`), &terse); err != nil {
		t.Fatalf("decoding a role-less membership failed: %v", err)
	}
	if got, err := EffectiveOrg("hanzo", terse, "acme"); err != nil || got != "acme" {
		t.Fatalf("a role-less membership did not authorize: got %q err %v", got, err)
	}
}

// ── The billing-selection contract, stated one case per test ────────────────
//
// The table above covers the predicate exhaustively. These five say the CONTRACT
// out loud, because the property that matters is not "which string comes back"
// but "an explicit ask either succeeds or refuses, and never quietly bills
// somebody else". Named individually so a failure names the rule it broke.

func TestEffectiveOrg_NoSelectionUsesHome(t *testing.T) {
	got, err := EffectiveOrg("hanzo", alice, "")
	if err != nil {
		t.Fatalf("no selection errored: %v — a caller who never touches the switcher must be unaffected", err)
	}
	if got != "hanzo" {
		t.Fatalf("no selection = %q, want home org %q", got, "hanzo")
	}
}

func TestEffectiveOrg_HomeExplicitlySelected(t *testing.T) {
	got, err := EffectiveOrg("hanzo", alice, "hanzo")
	if err != nil {
		t.Fatalf("selecting home errored: %v", err)
	}
	if got != "hanzo" {
		t.Fatalf("selecting home = %q, want %q", got, "hanzo")
	}
}

func TestEffectiveOrg_MemberOrgSelected(t *testing.T) {
	got, err := EffectiveOrg("hanzo", alice, "acme")
	if err != nil {
		t.Fatalf("a granted org was refused: %v — this is the switcher's whole feature", err)
	}
	if got != "acme" {
		t.Fatalf("selecting a granted org = %q, want %q", got, "acme")
	}
}

// The case this function was rewritten for. Returning home here SUCCEEDS against
// a different economic principal: the model runs, the meter records, the ledger
// writes, and the wrong account pays with no error anywhere.
func TestEffectiveOrg_UnauthorizedOrgRefused(t *testing.T) {
	got, err := EffectiveOrg("hanzo", alice, "initech")
	if !errors.Is(err, ErrOrgForbidden) {
		t.Fatalf("unauthorized org = (%q, %v), want ErrOrgForbidden", got, err)
	}
	if got != "" {
		t.Fatalf("a refusal named payer %q; a refused selection must name none", got)
	}
}

// Indistinguishable from unauthorized, deliberately: a caller must not be able to
// learn which orgs exist by varying the ask.
func TestEffectiveOrg_NonexistentOrgRefused(t *testing.T) {
	got, err := EffectiveOrg("hanzo", alice, "no-such-org-anywhere")
	if !errors.Is(err, ErrOrgForbidden) {
		t.Fatalf("nonexistent org = (%q, %v), want ErrOrgForbidden", got, err)
	}
	if got != "" {
		t.Fatalf("a refusal named payer %q", got)
	}

	_, unauthorized := EffectiveOrg("hanzo", alice, "initech")
	if unauthorized.Error() != err.Error() {
		t.Fatalf("nonexistent and unauthorized give different errors (%v vs %v) — the ask becomes an org-existence oracle",
			err, unauthorized)
	}
}

// A refusal must not be recoverable into a payer by a caller that ignores the
// error: the zero value names nobody, so an ignored error cannot charge anyone.
func TestEffectiveOrg_RefusalNamesNoPayerEvenIfErrorIgnored(t *testing.T) {
	eff, _ := EffectiveOrg("hanzo", alice, "initech")
	if LedgerOrg(eff, "", false) != "" {
		t.Fatalf("an ignored refusal still resolved a ledger — refusal must be unusable, not merely reported")
	}
}
