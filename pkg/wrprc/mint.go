package wrprc

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

// maxValidity is the ceiling GEN-5.2.4-08 places on a WRPRC: exp must be no
// later than 12 months after iat.
const maxValidity = 365 * 24 * time.Hour

// Signer mints WRPRCs on behalf of a provider of registration certificates.
type Signer struct {
	// Chain is the signing certificate followed by any intermediates, leaf first.
	Chain []*x509.Certificate
	Key   crypto.Signer
}

// Mint produces a compact JWS with media type rc-wrp+jwt over the payload.
//
// The signing certificate chain is carried in x5c so a consumer can build a path
// to a registration-certificate-provider trust anchor.
func (s *Signer) Mint(p Payload) (string, error) {
	if len(s.Chain) == 0 {
		return "", fmt.Errorf("wrprc: signer has no certificate chain")
	}
	if len(p.Entitlements) == 0 {
		return "", fmt.Errorf("wrprc: at least one entitlement is required (GEN-5.2.4-03)")
	}
	if p.Sub == "" {
		return "", fmt.Errorf("wrprc: sub is required")
	}

	if p.IssuedAt == 0 {
		p.IssuedAt = time.Now().UTC().Unix()
	}
	if p.ExpiresAt == 0 {
		p.ExpiresAt = time.Unix(p.IssuedAt, 0).Add(maxValidity).Unix()
	}
	if p.ExpiresAt > time.Unix(p.IssuedAt, 0).Add(maxValidity).Unix() {
		return "", fmt.Errorf("wrprc: exp exceeds iat + 12 months (GEN-5.2.4-08)")
	}
	if len(p.PolicyID) == 0 {
		p.PolicyID = []string{PolicyOIDWRPRC}
	}

	// provides_attestations only belongs on a provider (GEN-5.2.4-05). Emitting
	// it for a plain Service_Provider would assert an issuance right that the
	// register never granted.
	if len(p.ProvidesAttestations) > 0 {
		isProvider := false
		for _, e := range p.Entitlements {
			if IsProviderEntitlement(e) {
				isProvider = true
				break
			}
		}
		if !isProvider {
			return "", fmt.Errorf("wrprc: provides_attestations requires a provider entitlement (GEN-5.2.4-05)")
		}
	}

	x5c := make([]string, len(s.Chain))
	for i, c := range s.Chain {
		x5c[i] = base64.StdEncoding.EncodeToString(c.Raw)
	}
	header := map[string]any{
		"typ": MediaType,
		"alg": "ES256",
		"x5c": x5c,
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("wrprc: marshal header: %w", err)
	}
	payloadJSON, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("wrprc: marshal payload: %w", err)
	}

	enc := base64.RawURLEncoding
	signingInput := enc.EncodeToString(headerJSON) + "." + enc.EncodeToString(payloadJSON)

	digest := sha256.Sum256([]byte(signingInput))
	sig, err := s.sign(digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + enc.EncodeToString(sig), nil
}

// sign produces a JWS ES256 signature: the raw r||s pair, each padded to the
// curve size. crypto/ecdsa emits ASN.1 DER, which is not what JWS expects.
func (s *Signer) sign(digest []byte) ([]byte, error) {
	der, err := s.Key.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("wrprc: sign: %w", err)
	}
	var parsed struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &parsed); err != nil {
		return nil, fmt.Errorf("wrprc: decode signature: %w", err)
	}
	pub, ok := s.Key.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("wrprc: ES256 requires an ECDSA key, got %T", s.Key.Public())
	}
	size := (pub.Curve.Params().BitSize + 7) / 8
	out := make([]byte, 2*size)
	parsed.R.FillBytes(out[:size])
	parsed.S.FillBytes(out[size:])
	return out, nil
}
