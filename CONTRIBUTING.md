# Contributing

## Workflow

`main` is protected. Every change goes through a pull request, including small
ones — the diff and its checks are the review surface.

```sh
git switch -c fix/short-description
# ... change, then before pushing:
make test          # or: make test-softhsm, to include the PKCS#11 suite
make lint
git push -u origin fix/short-description
gh pr create
```

These checks must pass before a PR can merge: `test`, `test-softhsm`, `lint`,
`build`, `analyze (go)`, `govulncheck` and `SonarCloud Scan`. SBOM and Scorecard
run on `main` only, so they are not merge gates.

## Prerequisites

- Go as pinned in `go.mod`
- `softhsm2` and `opensc` for the PKCS#11 tests (`make test-softhsm`)
- Build with `GOWORK=off` if you have this checked out inside a Go workspace

## What the tests are for

This is certificate-minting code, so the tests are mostly about conformance and
about failing closed. When changing anything that shapes a certificate or a
signed document, add a test that pins the rule and cite the clause it comes
from, as the existing ones do. Two rules earned their tests the hard way:

- **EN 319 412-2 and EN 319 412-3 are disjoint profiles.** A legal person's
  identifier goes in `organizationIdentifier` (2.5.4.97); a natural person's
  goes in `serialNumber` (2.5.4.5). Never both, never the other one.
- **JWS ES256 signatures are raw `r||s`.** `crypto/ecdsa` returns ASN.1 DER, and
  signing with those bytes produces a token every verifier rejects while looking
  like a key problem.

## Scope

This is development and test tooling. It is not a supervised trust service, and
certificates it mints have no standing outside a test ecosystem. Changes that
would imply otherwise — key escrow, production key handling, anything that reads
as a real Registrar — belong in a different project.
