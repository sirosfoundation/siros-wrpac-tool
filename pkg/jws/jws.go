// Package jws produces compact ES256 JSON Web Signatures.
//
// It exists so the ASN.1-to-raw signature conversion is written once. Go's
// crypto/ecdsa emits DER-encoded (r, s); JWS requires the two integers
// concatenated and left-padded to the curve size. Signing with the DER bytes
// produces a token every verifier rejects, and the failure looks like a key
// mismatch rather than an encoding bug.
package jws

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"time"
)

// SignJAdES returns a compact JWS over raw payload bytes carrying the JAdES-B-B
// headers of ETSI TS 119 182-1: the signing time in iat and the SHA-256
// thumbprint of the signing certificate in x5t#S256.
//
// It exists so a LoTE can be signed by a key on a PKCS#11 token. g119612 ships
// its own PKCS#11 signer, but that one drives the crypto11 stack while this tool
// uses go-cryptoutil's — and two stacks calling C_Initialize on the same module
// in one process is precisely the conflict this package's callers already hit.
func SignJAdES(payload []byte, key crypto.Signer, chain []*x509.Certificate) (string, error) {
	if len(chain) == 0 {
		return "", fmt.Errorf("jws: JAdES requires a signing certificate")
	}
	thumb := sha256.Sum256(chain[0].Raw)
	header := map[string]any{
		"alg":      "ES256",
		"iat":      time.Now().UTC().Unix(),
		"x5t#S256": base64.RawURLEncoding.EncodeToString(thumb[:]),
		"x5c":      encodeChain(chain),
	}
	return signWithHeader(header, payload, key)
}

// Sign returns a compact JWS over payload, with typ in the protected header and
// the certificate chain (leaf first) in x5c when one is supplied.
func Sign(typ string, payload any, key crypto.Signer, chain []*x509.Certificate) (string, error) {
	header := map[string]any{"typ": typ, "alg": "ES256"}
	if len(chain) > 0 {
		header["x5c"] = encodeChain(chain)
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("jws: marshal payload: %w", err)
	}
	return signWithHeader(header, payloadJSON, key)
}

// signWithHeader serialises the protected header and signs the payload bytes.
func signWithHeader(header map[string]any, payload []byte, key crypto.Signer) (string, error) {
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("jws: marshal header: %w", err)
	}

	enc := base64.RawURLEncoding
	signingInput := enc.EncodeToString(headerJSON) + "." + enc.EncodeToString(payload)

	digest := sha256.Sum256([]byte(signingInput))
	sig, err := signES256(key, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + enc.EncodeToString(sig), nil
}

func encodeChain(chain []*x509.Certificate) []string {
	x5c := make([]string, len(chain))
	for i, c := range chain {
		x5c[i] = base64.StdEncoding.EncodeToString(c.Raw)
	}
	return x5c
}

// signES256 signs a digest and re-encodes the DER signature as raw r||s.
func signES256(key crypto.Signer, digest []byte) ([]byte, error) {
	der, err := key.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("jws: sign: %w", err)
	}
	var parsed struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &parsed); err != nil {
		return nil, fmt.Errorf("jws: decode signature: %w", err)
	}
	pub, ok := key.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("jws: ES256 requires an ECDSA key, got %T", key.Public())
	}
	size := (pub.Curve.Params().BitSize + 7) / 8
	out := make([]byte, 2*size)
	parsed.R.FillBytes(out[:size])
	parsed.S.FillBytes(out[size:])
	return out, nil
}
