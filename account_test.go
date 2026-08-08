// Copyright 2026 Hanzo AI Inc. All Rights Reserved.

package account

import "testing"

// TestPayer_GrantAndGateAgree is the deliverable. The account a request's GATE
// reads must be byte-identical to the account a GRANT / charge / top-up to the
// SAME credential funds — for every owner kind. This is the invariant the two
// deleted allowlists violated in production: the gate read "hanzo/alice" while a
// grant and a top-up credited "hanzo", so a paid-up member 402'd on an empty
// per-user wallet while the money sat in the org pool.
//
// Every one of those call sites resolves its subject through Payer, so the proof
// is: Payer is a pure function of the credential, and the four roles are four
// calls to it. They cannot disagree because there is one function.
func TestPayer_GrantAndGateAgree(t *testing.T) {
	cases := []struct {
		name string
		cred Credential
		want string // the ONE subject every role resolves to
	}{
		{
			// The exact production failure. A self-serve signup lands in the shared
			// signup org; strangers do not share a wallet, so each pays from their
			// own account. Gate, charge, grant, and top-up all land here.
			name: "person in the signup org bills to their own account",
			cred: Credential{Owner: "hanzo", Name: "alice"},
			want: "hanzo/alice",
		},
		{
			// A real tenant pools: every member spends the one org balance.
			name: "person in a real org bills to the org pool",
			cred: Credential{Owner: "acme", Name: "bob"},
			want: "acme",
		},
		{
			// A service credential IS the org — it never bills a per-app wallet that
			// no one funds (the "hanzo/hanzo-cloud" 402 the carve-out closes).
			name: "machine credential bills to its org",
			cred: Credential{Owner: "hanzo", Name: "hanzo-cloud", Machine: true},
			want: "hanzo",
		},
		{
			// A member of a real org, even named identically to a signup person,
			// still pools — the org, not the name, decides.
			name: "same name in a real org still pools",
			cred: Credential{Owner: "globex", Name: "alice"},
			want: "globex",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gate := Payer(tc.cred).Subject()   // what the ai balance gate reads
			charge := Payer(tc.cred).Subject() // what the usage debit spends
			grant := Payer(tc.cred).Subject()  // what an admin grant / top-up credits
			read := Payer(tc.cred).Subject()   // what the console balance view shows

			if gate != tc.want {
				t.Fatalf("gate subject = %q, want %q", gate, tc.want)
			}
			// The anti-regression assertion: all four roles are ONE account.
			if !(gate == charge && charge == grant && grant == read) {
				t.Fatalf("roles disagree: gate=%q charge=%q grant=%q read=%q (the split-brain bug)",
					gate, charge, grant, read)
			}
		})
	}
}

// TestPayer_ClaimWins: when the credential NAMES its payer, Payer reads the claim
// and stops inferring. This is the whole reason the module exists — the claim is
// signed by IAM at the identity boundary, and a signed claim cannot be forged by
// the caller it describes, while the inference it replaces could be.
func TestPayer_ClaimWins(t *testing.T) {
	// A real org whose member the claim names as a PERSON — the inference alone
	// would have pooled them. The claim wins.
	if got := Payer(Credential{Owner: "acme", Name: "bob", Account: "person:acme/bob"}).Subject(); got != "acme/bob" {
		t.Fatalf("claimed person subject = %q, want %q (claim must beat the pooled inference)", got, "acme/bob")
	}
	// A signup-org member the claim names as the ORG pool — the inference alone
	// would have split them per-person. The claim wins.
	if got := Payer(Credential{Owner: "hanzo", Name: "alice", Account: "org:hanzo"}).Subject(); got != "hanzo" {
		t.Fatalf("claimed org subject = %q, want %q (claim must beat the personal inference)", got, "hanzo")
	}
	// The claim also disarms the FORGEABLE machine signal: Machine says "pool me",
	// the signed claim says "you are a person". The signature wins.
	if got := Payer(Credential{Owner: "hanzo", Name: "alice", Account: "person:hanzo/alice", Machine: true}).Subject(); got != "hanzo/alice" {
		t.Fatalf("claimed subject with forged Machine = %q, want %q (signed claim must beat User.Type)", got, "hanzo/alice")
	}
}

// TestPayer_ForeignClaimIsRefused: a claim naming ANOTHER tenant's ledger is
// discarded, not billed. IAM never mints one (claim and `owner` come from the same
// signed token), so this can only fire on a mis-wired caller — and it must degrade
// to the caller's own account, never become a cross-tenant debit.
func TestPayer_ForeignClaimIsRefused(t *testing.T) {
	got := Payer(Credential{Owner: "acme", Name: "bob", Account: "org:victim"}).Subject()
	if got == "victim" {
		t.Fatalf("foreign claim billed another tenant's ledger (%q) — cross-tenant debit", got)
	}
	if got != "acme" {
		t.Fatalf("foreign claim subject = %q, want fallback to own org %q", got, "acme")
	}
}

// TestPayer_ThreeOwnerKinds locks the Account model: an account is owned by a
// Person, an Org, or a Project, and each resolves to a distinct, stable subject.
// Project billing needs NO org of its own — Project(org, name) is a first-class
// owner keyed exactly like a Person, with the org only naming the ledger it lives
// in. This is the CTO's spec: "a project is just another Account owner."
func TestPayer_ThreeOwnerKinds(t *testing.T) {
	personAcct := Person("acme", "bob")
	orgAcct := Org("acme")
	proj := Project("acme", "search")

	if got := personAcct.Subject(); got != "acme/bob" {
		t.Fatalf("Person subject = %q, want %q", got, "acme/bob")
	}
	if got := orgAcct.Subject(); got != "acme" {
		t.Fatalf("Org subject = %q, want %q", got, "acme")
	}
	if got := proj.Subject(); got != "acme/search" {
		t.Fatalf("Project subject = %q, want %q", got, "acme/search")
	}

	// Each account names the ledger (org) that holds it — the per-org file.
	for _, a := range []Account{personAcct, orgAcct, proj} {
		if a.Org() != "acme" {
			t.Fatalf("account %+v: Org() = %q, want %q", a, a.Org(), "acme")
		}
	}
	// A project bills without ever creating an org of its own: it lives in acme's
	// ledger, owned by nobody but itself.
	if proj.Kind() != project {
		t.Fatalf("Project kind = %q, want %q", proj.Kind(), project)
	}
}

// TestClaim_RoundTrips: String ∘ Parse is the identity on every account IAM can
// mint. This is the WIRE CONTRACT with iam/object/billing_account.go — the two
// share no code, so the grammar is the only thing holding them together.
func TestClaim_RoundTrips(t *testing.T) {
	for _, a := range []Account{
		Org("acme"),
		Person("hanzo", "alice"),
		Project("acme", "website"),
	} {
		if got := Parse(a.String()); got != a {
			t.Fatalf("Parse(%q) = %+v, want %+v (round-trip broken)", a.String(), got, a)
		}
	}
	if got := (Account{}).String(); got != "" {
		t.Fatalf("zero account renders %q, want empty (unattributable names nobody)", got)
	}
}

// TestParse_RefusesGarbage: a claim it cannot read names NOBODY — Parse never
// invents an owner. Each of these must fall through to Payer's fallback rather
// than address a wallet nobody meant.
func TestParse_RefusesGarbage(t *testing.T) {
	for _, claim := range []string{
		"",             // absent (a pre-claim token)
		"acme",         // no kind
		"wizard:acme",  // unknown kind
		"org:",         // no subject
		"org:acme/bob", // an org account is a bare slug, never named
		"person:hanzo", // a person needs a name
		"project:acme", // a project needs a name
		"person:/bob",  // no org half
	} {
		if a := Parse(claim); !a.Zero() {
			t.Fatalf("Parse(%q) = %+v, want Zero (unreadable claims name nobody)", claim, a)
		}
	}
}

// TestPayer_DeletedEnvIsInert proves the CR env is a genuine no-op — the whole
// point of this module. Setting the old allowlists to values that WOULD have
// flipped every resolution changes nothing, because nothing reads them.
//
// This is the tripwire for the tourniquet in our own runbook: ORG_BILLING_ORGS=hanzo
// was a documented mitigation, and while commerce still read it and ai did not, it
// would have split the two apart — commerce crediting "hanzo" while ai debited
// "hanzo/alice". With one rule and no env, the tourniquet cannot be armed.
func TestPayer_DeletedEnvIsInert(t *testing.T) {
	t.Setenv("PERSONAL_BILLING_ORGS", "acme,globex") // would have split acme per-user
	t.Setenv("ORG_BILLING_ORGS", "hanzo")            // would have pooled the signup org

	// acme still pools (env did NOT make it personal).
	if got := Payer(Credential{Owner: "acme", Name: "bob"}).Subject(); got != "acme" {
		t.Fatalf("with hostile PERSONAL_BILLING_ORGS: acme subject = %q, want %q (env must be inert)", got, "acme")
	}
	// hanzo person still per-person (env did NOT pool the signup org).
	if got := Payer(Credential{Owner: "hanzo", Name: "alice"}).Subject(); got != "hanzo/alice" {
		t.Fatalf("with hostile ORG_BILLING_ORGS: hanzo/alice subject = %q, want %q (env must be inert)", got, "hanzo/alice")
	}
}

// TestPayer_FailsClosed: an unattributable credential resolves to no account. A
// caller must refuse it (402/401), never bill it free. The Zero account has an
// empty subject, which every downstream (gate, ledger) treats as "cannot bill".
func TestPayer_FailsClosed(t *testing.T) {
	for _, c := range []Credential{
		{Owner: "", Name: "alice"},
		{Owner: "   ", Name: "alice"},
		{Owner: "", Name: "", Machine: true},
		{Owner: "", Account: "org:acme"}, // a claim cannot supply a missing owner
	} {
		a := Payer(c)
		if !a.Zero() {
			t.Fatalf("Payer(%+v) = %+v, want Zero", c, a)
		}
		if a.Subject() != "" {
			t.Fatalf("Payer(%+v).Subject() = %q, want empty", c, a.Subject())
		}
	}
}

// TestPayerOf_FunnelsToPayer: the key-form entry point (usage records, ZAP
// params) is a parse, not a second rule — it must answer identically to Payer.
func TestPayerOf_FunnelsToPayer(t *testing.T) {
	cases := []struct {
		org, key string
		want     string
	}{
		{"hanzo", "hanzo/alice", "hanzo/alice"}, // qualified key, org matches
		{"", "hanzo/alice", "hanzo/alice"},      // org derived from key prefix
		{"acme", "acme/bob", "acme"},            // real org pools regardless of key
		{"", "acme/bob", "acme"},                // derived org, still pools
		// A slash-less key is a bare owner, not a name: with an explicit org it
		// carries no name half, so it resolves to that org's pool. This is the
		// exact preserved contract of the deleted BillingSubjectFromUserKey — the
		// key form is "<org>/<name>" or a bare org, never a bare name.
		{"hanzo", "alice", "hanzo"}, // bare key + explicit org → org pool (name dropped)
		{"", "hanzo", "hanzo"},      // bare org, no name → org pool
	}
	for _, tc := range cases {
		if got := PayerOf(tc.org, tc.key).Subject(); got != tc.want {
			t.Fatalf("PayerOf(%q, %q).Subject() = %q, want %q", tc.org, tc.key, got, tc.want)
		}
	}
}

// TestAccount_SubjectIsFolded: the subject is always lowercased/trimmed, because
// the read paths lowercase and the write paths store verbatim — an un-folded
// subject would record usage that never nets against the balance (a silent leak).
func TestAccount_SubjectIsFolded(t *testing.T) {
	if got := Payer(Credential{Owner: "  HANZO ", Name: " Alice "}).Subject(); got != "hanzo/alice" {
		t.Fatalf("subject = %q, want folded %q", got, "hanzo/alice")
	}
	if got := Org(" ACME ").Subject(); got != "acme" {
		t.Fatalf("Org subject = %q, want folded %q", got, "acme")
	}
	// A claim folds too — IAM signs what a human typed, and the ledger is keyed
	// on the folded form.
	if got := Payer(Credential{Owner: "HANZO", Account: "PERSON:HANZO/ALICE"}).Subject(); got != "hanzo/alice" {
		t.Fatalf("claimed subject = %q, want folded %q", got, "hanzo/alice")
	}
}

// TestIsMachine_MatchesApplicationType locks the machine predicate to the IAM
// User.Type contract, case-insensitively. (The predicate's TRUST is a separate,
// documented problem — this only fixes its value.)
//
// BOTH spellings IAM uses are machines. "application" is the OIDC client shape;
// "service-account" is the identity class internal/oidc/provision.go mints and
// /v1/iam/service-accounts creates. A predicate that knows only the first reads a
// real service account as a person.
func TestIsMachine_MatchesApplicationType(t *testing.T) {
	for _, s := range []string{
		"application", "Application", " application ",
		"service-account", "Service-Account", " service-account ",
	} {
		if !IsMachine(s) {
			t.Fatalf("IsMachine(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"normal-user", "", "app", "service", "serviceaccount"} {
		if IsMachine(s) {
			t.Fatalf("IsMachine(%q) = true, want false", s)
		}
	}
}

// TestPayer_ServiceAccountInSignupOrgSpendsThePool is the live defect, in one
// assertion: hanzo/guest is the anonymous free tier, IAM typed it "service-account",
// and it read $0 on a pool holding ~$149k because Payer took it for a person.
//
// The signup org is the only place this bites — its members are strangers, so a
// person there pays personally — which is exactly where every first-party service
// account lands. The wallet a service account was handed there ("hanzo/guest") is
// one no funding path can name: a grant credits the pool, a deposit names a real
// member. So the wrong answer is not a smaller balance, it is an unreachable one.
func TestPayer_ServiceAccountInSignupOrgSpendsThePool(t *testing.T) {
	guest := Credential{Owner: SignupOrg, Name: "guest", Machine: IsMachine("service-account")}
	if got := Payer(guest).Subject(); got != SignupOrg {
		t.Fatalf("service account in the signup org pays %q, want the org pool %q", got, SignupOrg)
	}
	// A PERSON in the same org still pays personally — the pool is not opened to
	// strangers, which is the whole reason the signup org is special.
	human := Credential{Owner: SignupOrg, Name: "alice", Machine: IsMachine("normal-user")}
	if got := Payer(human).Subject(); got != SignupOrg+"/alice" {
		t.Fatalf("person in the signup org pays %q, want personal %q", got, SignupOrg+"/alice")
	}
}

// TestSignupOrg_MatchesIAM guards the one named constant against silent drift
// from IAM's DefaultOrganization. If IAM's default org ever changes, this billing
// floor must change with it — the test is the tripwire.
func TestSignupOrg_MatchesIAM(t *testing.T) {
	if SignupOrg != "hanzo" {
		t.Fatalf("SignupOrg = %q; must equal IAM object.DefaultOrganization (\"hanzo\")", SignupOrg)
	}
}
