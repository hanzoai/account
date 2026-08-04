# account

The billing-account rule. One value, one decision, no dependencies.

```go
account.Payer(account.Credential{Owner: org, Name: user, Account: claim}).Subject()
```

`(Org, Subject)` **is** the money's address — `Org` names the ledger that holds
it, `Subject` the key within that ledger. A deposit credits that address, the
spend-gate reads it, a usage debit spends it. One address, one answer, every
caller.

`Payer` is the whole point: it, and only it, decides whether a request pays from
an **org pool** or a **person's** own account. That decision shipped wrong twice
by being made in two places — a gate keyed on the pool while the debit spent a
person's wallet, so a funded pool green-lit a request that drained an empty
personal one, and an empty pool 402'd a funded person. Any new money path
resolves its address here rather than re-deriving it.

## Why it is its own module

It has **zero dependencies** — `go.mod` is two lines and the code imports only
`strings`. That is what lets every layer import it: cloud's trust boundary
(`clients/principal`), its metering middleware, and commerce's billing resolver
all call the same rule without any of them depending on each other.

Folding it into the commerce service would invert that: identity code would have
to import a ledger, a SQLite store and an HTTP surface to answer a pure question
about who pays.

## Layout

- `account.go` — `Account`, `Org`/`Person`/`Project`, `Parse`, `Payer`, `Credential`
- `org.go` — org-level helpers

Licensed under **MIT OR Apache-2.0**, per [HIP-0137](https://github.com/hanzoai/hips/blob/main/HIPs/hip-0137-one-license.md).
