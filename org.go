// Copyright 2026 Hanzo AI Inc. All Rights Reserved.

package account

// This file answers the question BEFORE "who pays": which org's ledger is this
// request spending from. Payer names the wallet; these two name the ledger the
// wallet lives in, and together they are the whole address.
//
// There is no personal org. Every self-serve signup lands in SignupOrg, so
// "Personal" is a WALLET (person:hanzo/alice) inside a ledger shared with every
// other stranger who signed up — Payer already draws that line. What was missing
// is the other axis: a member of several orgs picks one in the switcher, and the
// org they picked must be the org that pays.
//
// It did not. Each layer derived the org from a different place and they
// disagreed: the edge minted X-Org-Id from the `owner` claim, cloud honored a
// membership-gated selection, and ai read user.Owner and could not see a switch
// at all. So the gate could read one ledger while the debit landed on another —
// the same class of split the two deleted allowlists caused on the person axis,
// recurring on the org axis. These functions exist so the three layers run the
// SAME predicate rather than three that happen to agree until they do not.

// OrgRef is one entry of the signed `orgs` claim: an org the subject may act in
// and their coarse role there (owner | admin | member). IAM mints the set from
// the subject's real memberships, home org first, and omits the claim entirely
// for a machine principal (iam/internal/store.MemberOrgRefs).
//
// The JSON tags are the WIRE CONTRACT with IAM and are byte-identical to the
// three decoders that already exist independently in cloud, gateway and ai. It is
// declared here so those three can alias this type and decode one shape, rather
// than keep three hand-copies that can drift apart one field at a time.
type OrgRef struct {
	Org  string `json:"org"`
	Role string `json:"role,omitempty"`
}

// EffectiveOrg resolves the org a request ACTS IN: the org the client asked to
// act in if the signed claim set says they belong to it, otherwise their home
// org. It is the one org-switch predicate, and it is pure — the answer is a
// function of the token alone, with no lookup, so every layer that runs it on the
// same token gets the same answer.
//
// MEMBERSHIP COMES FROM THE SIGNED CLAIM, NEVER FROM THE REQUEST. `orgs` is
// decoded from a validated JWT; `requested` is the client's ask and carries no
// authority of its own. Honoring a raw client org would be a cross-tenant read —
// anyone could name any tenant and be believed. So the ask is only ever a
// SELECTION FROM a set IAM already granted, and the value returned on a match is
// the one from that set, so nothing a client typed can flow onward as an org.
//
// REFUSAL IS SILENT AND IS THE HOME ORG. A request outside the membership set,
// an empty set (a legacy pre-claim token, an opaque key, a machine principal),
// an empty ask, an unattributable subject — all resolve to home, which is the
// exact behavior of every one of these layers before a switch existed. There is
// no error return because there is no error: not switching is a valid outcome,
// and it is the outcome for every user who never touches the switcher. That makes
// adopting this function a provable no-op for them.
//
// THE COMPARISON IS VERBATIM: no trim, no case-fold. "acme" and "ACME" are
// DISTINCT orgs in IAM, so folding would let a member of one select the other,
// and trimming would let " acme" pass for a third. Byte-equality can only ever
// refuse a switch a looser rule would allow, and a refused switch is home — so
// the strict rule fails closed by construction. (Addressing folds; authorizing
// does not. Account.Subject lowercases so a write and a read net against the same
// balance. That is a different job: it canonicalizes a key AFTER this function has
// decided the caller may use it, and it must not be conflated with deciding.)
//
// Role is deliberately not read. Membership answers "may I act in this org at
// all"; what a role permits inside it is a separate authority, and braiding them
// here would put two decisions behind one call.
func EffectiveOrg(owner string, orgs []OrgRef, requested string) string {
	if owner == "" || requested == "" || requested == owner {
		return owner // no subject, no ask, or already home — nothing to decide
	}
	for _, o := range orgs {
		if o.Org == requested {
			return o.Org // the SIGNED slug, never the client's string
		}
	}
	return owner // outside the membership set — fail closed to home, silently
}

// LedgerOrg resolves the org that PAYS. It takes the org the request acts in
// (EffectiveOrg), the subject's home org, and whether the subject holds platform
// sudo — the reserved authority that lets a support admin act inside a customer's
// org without being a member of it.
//
// Two branches, deliberately not one clever expression, because they are two
// different policies that merely share a shape:
//
//	sudo   → home       an admin acting on a customer must never spend the
//	                    customer's money. Their org's data, our org's bill. A
//	                    support session that drains the account it was opened to
//	                    help is indistinguishable from theft, and the customer has
//	                    no way to see it happened.
//	anyone → effective  the switcher IS the payer selection. A member who picks a
//	                    team org spends the team's balance; that is the entire
//	                    feature, and the reason the two functions are separate:
//	                    acting somewhere and paying for it are the same answer for
//	                    everyone except sudo.
//
// Note that sudo AT HOME is not a special case — there effective already equals
// home, so the branch returns the value the other branch would have.
func LedgerOrg(effective, home string, sudo bool) string {
	if sudo {
		return home
	}
	return effective
}
