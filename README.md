# siros-wrpac-tool

A Registrar and Access CA for EUDI wallet-relying party certificates. It runs
small-scale deployments as well as one-shot test fixtures, and mints the two
certificates that identify a wallet-relying party to an EUDI Wallet:

- a **WRPAC** — Wallet-Relying Party Access Certificate, an X.509 certificate
  following the ETSI TS 119 411-8 profile
- a **WRPRC** — Wallet-Relying Party Registration Certificate, a signed JWT
  following ETSI TS 119 475 **V1.2.1**

Both apply to **issuers as well as verifiers**. Under CIR (EU) 2025/848 Annex I
point 12 a PID Provider or Attestation Provider registers as a wallet-relying
party in its own right, and per ETSI TS 119 472-3 `ISS-MDATA-4.2.1-02` an
issuer's WRPAC is the signing certificate of its OpenID4VCI Issuer Metadata.

> This is test and development tooling. It is not a supervised trust service, and
> the certificates it mints have no standing outside a test ecosystem.

## Why it exists

Nothing in the SIROS stack could previously mint a WRPAC or a WRPRC, which made
issuer-side access and registration certificate support untestable end to end.
This tool is the missing Registrar and Access CA.

## Usage

### Run a deployment

```sh
make build

# once — creates the Access CA and the registration certificate provider
./bin/siros-wrpac-tool init -d ./deployment --base-url https://registrar.example.org

# register a party and mint both of its certificates
./bin/siros-wrpac-tool issue -d ./deployment \
  --name "Example PID Provider" --organization "Example Provider GmbH" \
  --identifier LEIXG-529900T8BM49AURSDO55 \
  --support-uri https://example.org/support \
  --entitlement https://uri.etsi.org/19475/Entitlement/PID_Provider \
  --vct urn:eudi:pid:1 --doctype eu.europa.ec.eudi.pid.1

./bin/siros-wrpac-tool list -d ./deployment
./bin/siros-wrpac-tool revoke -d ./deployment <serial>
./bin/siros-wrpac-tool serve -d ./deployment --addr :8080
```

`siros-wrpac-tool entitlements` prints the accepted `--entitlement` URIs and
marks the four that may carry `provides_attestations`.

### What a deployment holds

| Path | What it is |
| --- | --- |
| `ca.pem` / `ca.key` | Access CA — configure `ca.pem` as the trust anchor |
| `registrar.pem` / `registrar.key` | the registration certificate provider |
| `register.json` | the register: identifiers, entitlements, status indices, revocations |
| `issued/<serial>.pem` | every certificate issued |
| `issued/<serial>.d/` | the party's own material: `wrpac.pem`, `wrpac.key`, `wrprc.jwt` |
| `public/` | what `serve` publishes |

`serve` exposes `/crl.der`, `/status-list.jwt`, `/register.json` and `/ca.pem`
with the media types their consumers expect. It speaks plain HTTP — put it
behind a reverse proxy, because the base URL burned into every issued
certificate is `https` and a wallet will refuse to fetch over `http`.

### Deployment state that must be preserved

`init` refuses to run twice against the same directory. Three things in
`register.json` cannot be regenerated:

- the **CA key**, which is the trust anchor relying parties have configured;
- the **CRL number**, which RFC 5280 requires to increase — a deployment that
  restarted and began again at 1 would have its CRLs ignored as stale;
- **status list indices**, which are allocated once and never reused. Reusing a
  slot would transfer a previous holder's revocation to a new certificate.

### Driving it from a git repository

For anything with more than a couple of clients, keep the registrations in git
and reconcile from them rather than running `issue` by hand.

```
clients/
  example-pid-provider.yaml    the registration
  example-pid-provider.csr     the client's certificate signing request
```

```sh
siros-wrpac-tool apply -d ./deployment --from ./clients --dry-run   # show the plan
siros-wrpac-tool apply -d ./deployment --from ./clients             # make it so
```

See [`examples/`](examples/) for a commented spec file.

**The repository is the source of truth; the register is derived from it.** That
split is the point: a future management UI only ever writes YAML and commits,
and never touches the deployment's store, so the two can be built and replaced
independently.

**Clients keep their own keys.** Each spec names a CSR. The deployment certifies
the public key in it and never holds the private half, so neither the repository
nor the deployment stores a client secret. The CSR's self-signature is checked
on load — that is the proof of possession, and skipping it would let anyone have
a certificate issued over someone else's key.

Reconciliation is by client id (the `id` field, defaulting to the filename stem —
never change it, it is what ties a file to its register entry). What happens:

| In the repo | In the register | Action |
| --- | --- | --- |
| present | absent | issue |
| changed (incl. a rotated CSR key) | present | re-issue, and revoke what it replaces as `superseded` |
| `revoked: true` | active | revoke |
| absent | active | nothing, unless `--prune` |

**Deleting a spec file does not revoke** unless you pass `--prune`. Revocation is
close to irreversible, and an accidentally deleted file should not take a
production relying party out of service. Setting `revoked: true` is the
reversible way to take a client out.

Unknown YAML keys are an error rather than being ignored — a misspelled
`entitlments:` would otherwise issue a certificate with no entitlements at all.

### One-shot fixtures

`sandbox` still emits a throwaway set in a single command, for when a test needs
material rather than a running registrar.

```sh
./bin/siros-wrpac-tool sandbox --out ./out
```

## What the profile enforces

A WRPAC that fails any of these is rejected at mint time rather than shipped:

- `keyUsage` includes **nonRepudiation** (contentCommitment). It is deliberately
  not exclusive — the same certificate may also carry `digitalSignature`, which
  is what lets one WRPAC serve both request signing and metadata signing.
- `subjectAltName` carries at least one contact URI or email.
- `certificatePolicies` asserts one of the four TS 119 411-8 policy OIDs
  (`0.4.0.194118.1.1`–`.4`), selected by subject kind and assurance level.

A WRPRC is likewise checked before signing:

- at least one entitlement (`GEN-5.2.4-03`)
- `provides_attestations` only alongside a provider entitlement (`GEN-5.2.4-05`)
- `exp` no later than `iat` + 12 months (`GEN-5.2.4-08`)

## Two conformance notes

**`organizationIdentifier` vs `serialNumber`.** ETSI EN 319 412-3 clause 4.2.1
requires `organizationIdentifier` (OID 2.5.4.97) for legal persons. `go-trust`'s
`rpcert.WRPACProfile.ExtractIdentity` currently reads `Subject.SerialNumber`
(2.5.4.5) and reports it as `organization_identifier`. Until that is corrected,
issued certificates carry the identifier in **both** attributes so that a
standards-conformant consumer and the current extractor resolve the same value.

**V1.2.1 field spellings.** This tool emits TS 119 475 **V1.2.1**. `go-trust`
models V1.1.1 and will mis-parse a V1.2.1 document — most consequentially it
hard-fails on a flat `sub` and silently drops `claim`, yielding an empty
allowed-attribute set that reads as "may request nothing". The differences are
recorded in `pkg/wrprc.FieldNotes`.

### LoTE publication

A wallet needs this deployment's Access CA and registration certificate provider
as trust anchors before it can verify anything issued here.

```sh
./bin/siros-wrpac-tool lote -d ./deployment --territory SE
```

The document is built with **g119612's own types**, so there is one
implementation of the ETSI TS 119 602 schema in the ecosystem rather than two,
and it is written in the same layout g119612's `publish-lote` pipeline step
produces — `lote.json` plus a JAdES-B-B `lote.json.jws` alongside it. The
filename follows the distribution point, matching `publish-lote`'s own naming, so
output drops straight into a `tsl-tool` pipeline directory and `go-trust`'s
`pkg/registry/lote` consumes it unchanged.

The sequence number must increase on every republication; it defaults to the
deployment's CRL number, which already advances on every change.

> The two service type identifiers are expressed under the ETSI 19475 namespace,
> because TS 119 612's registry has no entries for WRP access and registration
> certificate providers yet. Revisit when the official identifiers are published.

### Keys on a PKCS#11 token

```sh
export SIROS_WRPAC_PKCS11_PIN=...
./bin/siros-wrpac-tool init -d ./deployment \
  --base-url https://registrar.example.org \
  --pkcs11-module /usr/lib/softhsm/libsofthsm2.so \
  --pkcs11-token siros \
  --ca-key-label wrpac-ca --registrar-key-label wrpac-registrar
```

The keys must already exist on the token — this tool certifies them, it does not
create them. With `--pkcs11-module` no private key is ever written to disk.

**The PIN is never persisted.** `register.json` records the module, token and key
labels, plus the *name* of the environment variable to read the PIN from. A
register file gets copied, committed and shared; a PIN in it would follow.

## Revocation

Both mechanisms move together. `revoke` puts the WRPAC serial on the CRL **and**
sets the WRPRC's status list bit, because revoking only one leaves the party
usable through the other.

The CRL is published even when nothing is revoked. "Nothing is revoked" is a
different statement from "no CRL available", and a consumer that cannot fetch a
CRL should not read that as evidence of revocation.

## Not yet implemented

- **LoTE publication.** Access CA and registration-certificate-provider trust
  anchors should be published as an ETSI TS 119 602 List of Trusted Entities that
  `go-trust`'s `pkg/registry/lote` already consumes. That format is owned by the
  `trust-lists` repository and the `g119612` library; this tool should reuse them
  rather than reimplement the schema.
- **TLS.** `serve` is plain HTTP by design; terminate TLS in front of it.
- **Signing an issued party's key on a token.** The CA and registrar keys can
  live on a PKCS#11 token; keys issued *to* relying parties are still generated
  in software, since they belong to the party rather than the deployment.

## A note on `replace`

`go.mod` carries a `replace` for `github.com/moov-io/signedxml`, because g119612
needs a fork that upstream does not carry. Go ignores `replace` directives in
dependencies, so importing `pkg/lote` from another module means adding the same
line there.

## Docker

```sh
docker build -t siros-wrpac-tool .
docker compose up          # serves a registrar on :8080 from ./deployment
```

The image is statically linked but keeps cgo, because PKCS#11 needs it. SoftHSM
is installed so a deployment can be exercised without real hardware; for a
production token, mount the vendor's PKCS#11 module and point
`--pkcs11-module` at it.

`/data/deployment` must be a persistent volume — it holds the CA key, the CRL
number and the status list indices.

## Standards basis

- ETSI TS 119 411-8 V1.1.1 (2025-10) — WRPAC certificate policy
- ETSI TS 119 475 V1.2.1 (2026-03) — WRPRC profile, entitlements, Annex A/C
- ETSI TS 119 472-3 V1.1.1 (2026-03) — Issuer Metadata carriage
- CIR (EU) 2025/848 — Annexes I, IV and V

## License

BSD 2-Clause. See [LICENSE](LICENSE).
