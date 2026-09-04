# siros-wrpac-tool

[![CI](https://github.com/sirosfoundation/siros-wrpac-tool/actions/workflows/ci.yml/badge.svg)](https://github.com/sirosfoundation/siros-wrpac-tool/actions/workflows/ci.yml)
[![Security](https://github.com/sirosfoundation/siros-wrpac-tool/actions/workflows/security.yml/badge.svg)](https://github.com/sirosfoundation/siros-wrpac-tool/actions/workflows/security.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/sirosfoundation/siros-wrpac-tool/badge)](https://scorecard.dev/viewer/?uri=github.com/sirosfoundation/siros-wrpac-tool)
[![Go Version](https://img.shields.io/github/go-mod/go-version/sirosfoundation/siros-wrpac-tool)](https://go.dev/)
[![GHCR](https://img.shields.io/badge/ghcr.io-sirosfoundation%2Fsiros--wrpac--tool-blue)](https://ghcr.io/sirosfoundation/siros-wrpac-tool)
[![License](https://img.shields.io/badge/License-BSD_2--Clause-blue.svg)](LICENSE)

An Access CA and Registrar for EUDI wallet-relying party certificates:

- **WRPAC** — an X.509 access certificate on the ETSI TS 119 411-8 profile
- **WRPRC** — a registration certificate as `rc-wrp+jwt`, ETSI TS 119 475 **V1.2.1**

Both apply to **issuers as well as verifiers**: under CIR (EU) 2025/848 a PID or
attestation provider is a registered wallet-relying party in its own right, and
per ETSI TS 119 472-3 an issuer's WRPAC signs its OpenID4VCI Issuer Metadata.

> Development and test tooling. Not a supervised trust service — certificates it
> mints have no standing outside a test ecosystem.

## Quick start

```sh
make build

# once: creates the Access CA and the registration certificate provider
./bin/siros-wrpac-tool init -d ./deployment --base-url https://registrar.example.org

# register a party from a spec + CSR, and mint both its certificates
./bin/siros-wrpac-tool apply -d ./deployment --from ./clients --dry-run
./bin/siros-wrpac-tool apply -d ./deployment --from ./clients

./bin/siros-wrpac-tool lote   -d ./deployment      # publish trust anchors
./bin/siros-wrpac-tool revoke -d ./deployment <serial>
./bin/siros-wrpac-tool serve  -d ./deployment --addr :8080
```

`sandbox` emits a throwaway set in one command when you want fixtures rather
than a running registrar. `entitlements` lists the accepted `--entitlement` URIs.

## How it is meant to be run

**A git repository of per-client YAML is the source of truth**; the deployment's
register is derived from it. `apply` reconciles the two. A future management UI
only ever writes YAML and commits — it never touches the store. See
[`examples/`](examples/) for a commented spec.

**Clients keep their own keys.** Each spec names a CSR; the deployment certifies
the public key and never holds the private half, so neither the repository nor
the deployment stores a client secret. The CSR's self-signature is checked on
load — that is the proof of possession.

**Deleting a spec does not revoke** without `--prune`. Revocation is close to
irreversible; `revoked: true` is the reversible way to take a client out.

**The deployment directory must persist.** It holds the CA key, the CRL number
(RFC 5280 requires it to increase) and status list indices (reusing a slot would
transfer a previous holder's revocation to a new certificate). `init` refuses to
run twice for the same reason.

## Revocation

`revoke` drives both mechanisms together — the WRPAC serial onto the CRL *and*
the WRPRC's status list bit. Revoking one alone leaves the party usable through
the other. The CRL is published even when empty: "nothing is revoked" is a
different statement from "no CRL available".

## Keys on a PKCS#11 token

```sh
export SIROS_WRPAC_PKCS11_PIN=...
./bin/siros-wrpac-tool init -d ./deployment --base-url https://registrar.example.org \
  --pkcs11-module /usr/lib/softhsm/libsofthsm2.so --pkcs11-token siros \
  --ca-key-label wrpac-ca --registrar-key-label wrpac-registrar
```

The keys must already exist on the token — this tool certifies keys, it does not
create them. With `--pkcs11-module` no private key is written to disk. **The PIN
is never persisted**: the register records only the name of the environment
variable to read it from.

## Docker

```sh
docker compose up      # serves a registrar on :8080 from ./deployment
```

Statically linked but with cgo, because PKCS#11 needs it. SoftHSM is installed so
a deployment can be exercised without real hardware; mount a vendor module for a
production token.

## Conformance notes

Certificates are validated against their profile before they are returned, so a
non-conformant one is a mint-time error rather than something a wallet discovers
later. Two rules that are easy to get wrong:

- **EN 319 412-2 and EN 319 412-3 are disjoint.** `LEG-4.2.1-1` disapplies the
  natural-person clause for legal persons, so the identifier goes in
  `organizationIdentifier` (2.5.4.97) for a legal person and `serialNumber`
  (2.5.4.5) for a natural person — never both. Requires go-trust **v0.20.0+**,
  which reads 2.5.4.97.
- **LoTE `ServiceStatus` must be absent** outside the PuB-EAA profile: presence
  in the list *is* the trust statement. Output is built from g119612's own types
  and written in `publish-lote`'s layout, so it drops into a `tsl-tool` pipeline
  directory unchanged.

`go.mod` carries a `replace` for `moov-io/signedxml` that g119612 needs. Go
ignores `replace` in dependencies, so importing `pkg/lote` elsewhere needs the
same line.

## Known limits

- `serve` is plain HTTP by design — terminate TLS in front of it.
- Keys issued *to* relying parties are software keys; they belong to the party.
- **Relying Party Services are not modelled.** ARF v3.0.0 and TS5 give a party a
  `services` array with a `serviceIdentifier` and bind WRPRC to WRPAC by both.
  One service per party is permitted when there is no intermediary, which is what
  this models — and ETSI TS 119 475 V1.2.1 has no service identifier field yet,
  so there is nowhere standards-defined to put one.

## Contributing

`main` is protected; changes go through a pull request. See
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

BSD 2-Clause. See [LICENSE](LICENSE).
