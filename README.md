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
- **Key protection.** Keys are PKCS#8 files with `0600` permissions. There is no
  HSM or PKCS#11 support, which is the main reason this is not a supervised
  trust service.

## Standards basis

- ETSI TS 119 411-8 V1.1.1 (2025-10) — WRPAC certificate policy
- ETSI TS 119 475 V1.2.1 (2026-03) — WRPRC profile, entitlements, Annex A/C
- ETSI TS 119 472-3 V1.1.1 (2026-03) — Issuer Metadata carriage
- CIR (EU) 2025/848 — Annexes I, IV and V

## License

BSD 2-Clause. See [LICENSE](LICENSE).
