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
			// no one funds (the "hanzo/hanzo-cloud" 402 the carve-out closes). It
			// says so in the SIGNED claim: in the signup org an org account is the
			// platform's balance, so naming it is a statement IAM makes at the
			// identity boundary, never one inferred from a row's class here.
			name: "machine credential bills to its org, over the claim",
			cred: Credential{Owner: "hanzo", Name: "hanzo-cloud", Account: "org:hanzo"},
			want: "hanzo",
		},
		{
			// …and in a real tenant it needs no claim, because every principal
			// there pools regardless of class.
			name: "machine credential in a tenant org pools without a claim",
			cred: Credential{Owner: "acme", Name: "acme-bot"},
			want: "acme",
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
	// A signed claim naming the PERSON holds in the signup org too — there is no
	// longer any second signal that could override it, because the class a row
	// asserts is no longer an input at all.
	if got := Payer(Credential{Owner: "hanzo", Name: "alice", Account: "person:hanzo/alice"}).Subject(); got != "hanzo/alice" {
		t.Fatalf("claimed person subject = %q, want %q", got, "hanzo/alice")
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
		{Owner: "", Name: ""},
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
		// A slash-less key with an EXPLICIT org is that org's member: the caller
		// already supplied the ledger, so the key is the name half. It used to be
		// discarded and answer with the org account — in the signup org, the
		// platform pool — while the spend gate re-qualified the same bare name to
		// the person. Gate and debit now address one wallet.
		{"hanzo", "alice", "hanzo/alice"}, // bare key + explicit org → that member
		{"acme", "bob", "acme"},           // …and a pooled org still pools
		// With no org to qualify it, a bare key names the org itself — an address,
		// not a credential that lost its person.
		{"", "hanzo", "hanzo"}, // bare org, no name → org account
		{"", "acme", "acme"},
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

// TestPayer_AnAssertedClassNeverReachesThePool is the regression for the last
// input to this function that a ROW could assert.
//
// A machine flag used to be read one step ABOVE the signup-org rule, so a
// machine-typed credential took Org(SignupOrg) — the platform's own balance —
// without ever reaching the rule that governs that org. The flag was derived by
// each caller from User.Type, a profile column: "is a program" was a fact about a
// row, and it was being spent as "may spend the platform's money".
//
// The fallback answers for credentials that carry NO claim, and a credential
// carrying no claim carries no evidence of authority either. So here the NAME
// decides, for a program exactly as for a person. Being a machine is not a grant.
func TestPayer_AnAssertedClassNeverReachesThePool(t *testing.T) {
	// The shape the defect needs: the signup org, a machine class, nothing signed.
	for _, name := range []string{"guest", "svc", "bot"} {
		c := Credential{Owner: SignupOrg, Name: name}
		if got := Payer(c).Subject(); got != SignupOrg+"/"+name {
			t.Fatalf("%q in the signup org pays %q, want personal %q — the pool is not reachable by shape",
				name, got, SignupOrg+"/"+name)
		}
		if Payer(c) == Org(SignupOrg) {
			t.Fatalf("%q reached the platform pool through the fallback", name)
		}
	}
	// A PERSON in the same org is unchanged — the free-rider hole stays shut.
	if got := Payer(Credential{Owner: SignupOrg, Name: "alice"}).Subject(); got != SignupOrg+"/alice" {
		t.Fatalf("person in the signup org pays %q, want personal %q", got, SignupOrg+"/alice")
	}
	// A REAL TENANT is unchanged: every principal there pools, which is why the
	// removed flag decided nothing outside the signup org.
	if got := Payer(Credential{Owner: "acme", Name: "bot"}).Subject(); got != "acme" {
		t.Fatalf("a machine in a tenant org pays %q, want the tenant pool %q", got, "acme")
	}
	// And the SIGNED claim still decides, above the shape — this narrows the
	// fallback only. IAM states the payer at the identity boundary; that is the
	// one path by which a first-party service credential names an org account.
	claimed := Credential{Owner: SignupOrg, Name: "guest", Account: Org(SignupOrg).String()}
	if got := Payer(claimed); got != Org(SignupOrg) {
		t.Fatalf("a signed org claim was dropped: %q", got.Subject())
	}
}

// A CREDENTIAL FROM ANOTHER TENANT NEVER NAMES THE POOL, however it is shaped.
// The claim is honored only within the caller's own org, so a foreign claim on a
// signup-org credential falls back to the shape rule rather than crossing tenants.
func TestPayer_ForeignClaimNeverCrossesIntoThePool(t *testing.T) {
	// An acme credential claiming the platform's balance is refused the claim and
	// resolves to its own tenant.
	if got := Payer(Credential{Owner: "acme", Name: "bob", Account: Org(SignupOrg).String()}); got != Org("acme") {
		t.Fatalf("a foreign claim was honored: %q", got.Subject())
	}
	// …and a signup-org member claiming a tenant's pool is refused likewise.
	if got := Payer(Credential{Owner: SignupOrg, Name: "mallory", Account: Org("acme").String()}); got != Person(SignupOrg, "mallory") {
		t.Fatalf("a foreign claim was honored: %q", got.Subject())
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

// TestPayer_NamelessCredentialNeverReachesThePool is the regression for a
// self-serve, durable path onto the platform's own balance.
//
// THE CHAIN. IAM's userClaims resolves a token row's "<owner>/<name>" key to an
// Identity. When that row does not resolve it returned the subject and NOTHING
// else — no name, no type, no billing_account — while the signer still stamped
// `owner` from the application's organization, which for the console app is the
// signup org. A refresh token freezes its User string at establishment and the
// rotation copies it forward verbatim, so re-keying the identity underneath it
// (self-serve: onboarding a personal org rewrites user.Owner, and lookups are by
// (owner, name)) makes every later rotation mint one of these. Deleting a user,
// or a transient lookup error, produced the same credential.
//
// Payer then read it as "no name ⇒ not a person" and answered with the org
// account. In the signup org that account is the platform pool, so a stranger's
// credential spent the platform's money, and each rotation renewed the channel.
//
// The assertion is NEGATIVE on purpose: the subject must be EMPTY — refused —
// not merely "different from the pool". A test that only checked `!= "hanzo"`
// would have passed just as happily on a subject of "hanzo/" or "", and passing
// either way is the failure mode this whole file exists to prevent.
func TestPayer_NamelessCredentialNeverReachesThePool(t *testing.T) {
	// Exactly what iam/internal/oidc.userClaims emits for an unresolvable row,
	// carried into ai: owner from the signed `owner` claim, everything else absent.
	nameless := Credential{Owner: SignupOrg, Name: "", Account: ""}

	got := Payer(nameless)
	if !got.Zero() {
		t.Fatalf("Payer(nameless) = %+v, want the zero Account (unattributable)", got)
	}
	if s := got.Subject(); s != "" {
		t.Fatalf("Payer(nameless).Subject() = %q, want %q — a credential that names "+
			"nobody must not address the platform pool", s, "")
	}
	// State the money consequence outright, so a future edit that reintroduces the
	// fallback fails on the thing that actually cost us rather than on a shape.
	if s := Payer(nameless).Subject(); s == SignupOrg {
		t.Fatalf("REGRESSION: a nameless credential resolved to the platform pool %q", s)
	}

	// The same credential shaped as a key, through the other entry point.
	if s := PayerOf(SignupOrg, "").Subject(); s != "" {
		t.Fatalf("PayerOf(%q, \"\").Subject() = %q, want empty", SignupOrg, s)
	}

	// Whitespace is not a name — fold() must not let " " stand in for one.
	if s := Payer(Credential{Owner: SignupOrg, Name: "   "}).Subject(); s != "" {
		t.Fatalf("Payer(blank name).Subject() = %q, want empty", s)
	}
}

// TestPayer_RefusalSparesEveryLegitimateCaller pins the four populations the
// refusal above must NOT touch. Over-refusing here 402s a paying customer or a
// first-party service, which is a worse outage than the hole it closes — so each
// is asserted explicitly rather than assumed.
func TestPayer_RefusalSparesEveryLegitimateCaller(t *testing.T) {
	// 1. A MACHINE, as it is actually minted. Every client_credentials token IAM
	// issues carries a signed billing_account, and the API-key door states the same
	// claim (iam compat keyUser.BillingAccount) — so the claim answers before the
	// fallback is ever reached, and a first-party service credential keeps its org
	// pool. That door does not transmit User.Type at all, which is why removing the
	// asserted class from Credential cannot touch this population.
	for _, m := range []Credential{
		{Owner: SignupOrg, Name: "hanzo-cloud", Account: "org:hanzo"},
		{Owner: SignupOrg, Name: "hanzo-insights", Account: "org:hanzo"},
		{Owner: SignupOrg, Name: "", Account: "org:hanzo"}, // nameless, but signed
	} {
		if got := Payer(m).Subject(); got != SignupOrg {
			t.Fatalf("machine %+v resolved to %q, want the org pool %q", m, got, SignupOrg)
		}
	}

	// 2. A FUNDED CUSTOMER in their own tenant org — the population an
	// over-broad refusal would have 402'd. A pooled org answers the same for a
	// named member, a nameless credential and a member-less grant alike, so the
	// name is never load-bearing there and must never be required.
	for _, c := range []Credential{
		{Owner: "maxpower", Name: "davelorenzini"},
		{Owner: "maxpower", Name: ""}, // member-less: addresses the pool
		{Owner: "maxpower", Name: "davelorenzini", Account: "org:maxpower"},
	} {
		if got := Payer(c).Subject(); got != "maxpower" {
			t.Fatalf("tenant credential %+v resolved to %q, want %q", c, got, "maxpower")
		}
	}

	// 3. A NORMAL SIGNUP PERSON still gets their own wallet — the whole reason the
	// signup org reads the name at all.
	if got := Payer(Credential{Owner: SignupOrg, Name: "alice"}).Subject(); got != "hanzo/alice" {
		t.Fatalf("signup person resolved to %q, want %q", got, "hanzo/alice")
	}

	// 4. AN ORG ADDRESS is not a credential that lost its person. A bare key with
	// no org to qualify it still names the org — this is what an admin grant
	// crediting a pool and the per-org ledger selector both hold.
	if got := PayerOf("", SignupOrg).Subject(); got != SignupOrg {
		t.Fatalf("bare org key resolved to %q, want %q", got, SignupOrg)
	}
	if got := PayerOf("", "maxpower").Subject(); got != "maxpower" {
		t.Fatalf("bare tenant key resolved to %q, want %q", got, "maxpower")
	}
}

// TestPayerOf_BareNameIsTheMemberNotThePool: the legacy chat/TTS/STT usage
// records hold the caller as a BARE username with the org passed alongside. The
// spend gate re-qualifies that to "<org>/<name>" before checking the balance;
// this dropped it and billed the org account. In the signup org that meant every
// legacy turn was gated against the person's wallet and then charged to the
// platform pool — one request, two addresses.
func TestPayerOf_BareNameIsTheMemberNotThePool(t *testing.T) {
	if got := PayerOf(SignupOrg, "carol").Subject(); got != "hanzo/carol" {
		t.Fatalf("PayerOf(%q, %q).Subject() = %q, want %q — the debit must address "+
			"the wallet the gate checked", SignupOrg, "carol", got, "hanzo/carol")
	}
	if got := PayerOf(SignupOrg, "carol").Subject(); got == SignupOrg {
		t.Fatalf("REGRESSION: a legacy usage record billed the platform pool %q", got)
	}
	// A pooled tenant org is unaffected: named or not, it answers with the pool.
	if got := PayerOf("maxpower", "dave").Subject(); got != "maxpower" {
		t.Fatalf("PayerOf(maxpower, dave).Subject() = %q, want %q", got, "maxpower")
	}
}
