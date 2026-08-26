package wrprc

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/sirosfoundation/siros-wrpac-tool/pkg/jws"
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
	if err := p.validate(); err != nil {
		return "", err
	}
	return jws.Sign(MediaType, p, s.Key, s.Chain)
}

// validate applies the TS 119 475 rules that can be checked before signing, and
// fills in the defaults the profile allows. Minting a document that violates
// them would produce a certificate that wallets reject, so this fails early
// rather than shipping one.
func (p *Payload) validate() error {
	if len(p.Entitlements) == 0 {
		return fmt.Errorf("wrprc: at least one entitlement is required (GEN-5.2.4-03)")
	}
	if p.Sub == "" {
		return fmt.Errorf("wrprc: sub is required")
	}

	if p.IssuedAt == 0 {
		p.IssuedAt = time.Now().UTC().Unix()
	}
	ceiling := time.Unix(p.IssuedAt, 0).Add(maxValidity).Unix()
	if p.ExpiresAt == 0 {
		p.ExpiresAt = ceiling
	}
	if p.ExpiresAt > ceiling {
		return fmt.Errorf("wrprc: exp exceeds iat + 12 months (GEN-5.2.4-08)")
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
			return fmt.Errorf("wrprc: provides_attestations requires a provider entitlement (GEN-5.2.4-05)")
		}
	}
	return nil
}
