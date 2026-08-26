# siros-wrpac-tool

Development tooling that mints the two certificates identifying a wallet-relying
party to an EUDI Wallet:

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

```sh
make build
./bin/siros-wrpac-tool sandbox --out ./out
```

`sandbox` writes a complete, self-consistent set:

| File | What it is |
| --- | --- |
| `ca.pem` / `ca.key` | Access CA — configure `ca.pem` as the trust anchor |
| `wrpac.pem` / `wrpac.key` | the relying party's access certificate; sign Issuer Metadata with this key |
| `registrar.pem` | the registration certificate provider's certificate |
| `wrprc.jwt` | the registration certificate (`rc-wrp+jwt`) |
| `crl.der` | an empty CRL |

Flags select the subject and what it is registered to issue:

```sh
./bin/siros-wrpac-tool sandbox \
  --entitlement https://uri.etsi.org/19475/Entitlement/QEAA_Provider \
  --vct urn:eudi:ehic:1 \
  --identifier LEIXG-529900T8BM49AURSDO55
```

The generated WRPAC is accepted by `go-trust`'s own
`rpcert.WRPACProfile.ValidateCredential`, which is the bar the plan sets for this
tool.

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

## Not yet implemented

- **LoTE publication.** Access CA and registration-certificate-provider trust
  anchors should be published as an ETSI TS 119 602 List of Trusted Entities that
  `go-trust`'s `pkg/registry/lote` already consumes. That format is owned by the
  `trust-lists` repository and the `g119612` library; this tool should reuse them
  rather than reimplement the schema.
- **Status list publication.** `wrprc.jwt` carries a `status.status_list`
  reference, but nothing serves the list yet.
- **Revocation of a minted certificate.** `CreateCRL` accepts entries; there is
  no command to revoke a previously issued certificate and republish.

## Standards basis

- ETSI TS 119 411-8 V1.1.1 (2025-10) — WRPAC certificate policy
- ETSI TS 119 475 V1.2.1 (2026-03) — WRPRC profile, entitlements, Annex A/C
- ETSI TS 119 472-3 V1.1.1 (2026-03) — Issuer Metadata carriage
- CIR (EU) 2025/848 — Annexes I, IV and V

## License

BSD 2-Clause. See [LICENSE](LICENSE).
