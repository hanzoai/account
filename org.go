// Copyright 2026 Hanzo AI Inc. All Rights Reserved.

package account

import "errors"

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
// AN EXPLICIT ASK EITHER SUCCEEDS OR REFUSES — IT NEVER FALLS BACK. This used
// to return home for an ask outside the membership set, and called that "fail
// closed". It is not. This function selects the PAYER, so falling back does not
// fail at all: it succeeds against a DIFFERENT economic principal. Everything
// downstream then behaves correctly — the model runs, the tokens meter, the
// ledger writes — while the wrong account is charged, and nobody sees an error
// because there wasn't one. An obvious failure would have been safer.
//
// So the ask is honored, or it is ErrOrgForbidden. NO ASK is still home: a
// caller who never touches the switcher is unchanged, which keeps adoption a
// no-op for them. The difference is only that naming an org you cannot bill is
// now an answer, not a silent redirection of the bill.
//
// UNAUTHORIZED AND NONEXISTENT ARE THE SAME REFUSAL, deliberately. Distinguishing
// them would let a caller probe which orgs exist by varying the ask. Callers
// surface both as 403.
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
func EffectiveOrg(owner string, orgs []OrgRef, requested string) (string, error) {
	if requested == "" || requested == owner {
		return owner, nil // no ask, or already home — nothing to decide
	}
	// An explicit selection requires an attributable subject. An empty owner is
	// unattributable, and answering it with ("", nil) would report success while
	// naming no payer — the same shape as the fallback this function was fixed to
	// remove, one level down.
	if owner == "" {
		return "", ErrOrgForbidden
	}
	for _, o := range orgs {
		if o.Org == requested {
			return o.Org, nil // the SIGNED slug, never the client's string
		}
	}
	// Outside the membership set. Refuse — do not redirect the bill.
	return "", ErrOrgForbidden
}

// ErrOrgForbidden is the refusal for an explicit org selection the subject's
// signed membership does not cover — whether the org is one they do not belong
// to or one that does not exist. Callers surface both as 403 so the ask cannot
// be used to enumerate orgs.
var ErrOrgForbidden = errors.New("account: org selection not permitted for this subject")

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
