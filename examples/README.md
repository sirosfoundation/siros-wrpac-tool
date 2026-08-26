# Example client repository

The layout `siros-wrpac-tool apply --from` expects. Keep it in git.

```
clients/
  example-pid-provider.yaml    the registration
  example-pid-provider.csr     the client's certificate signing request
```

A client generates its own key and CSR, and sends only the CSR:

```sh
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout private.key -out example-pid-provider.csr \
  -subj "/CN=Example PID Provider"
```

`private.key` never leaves the client. Commit the `.csr` and the `.yaml`.

Then, from the deployment operator's side:

```sh
siros-wrpac-tool apply -d ./deployment --from ./clients --dry-run
siros-wrpac-tool apply -d ./deployment --from ./clients
```

Issued material lands in `clients/<id>.issued/` as `wrpac.pem` and `wrprc.jwt`.
Both are public, so they can be committed back alongside the request that
produced them.
