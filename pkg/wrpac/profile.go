// Package wrpac issues Wallet-Relying Party Access Certificates (WRPACs)
// conforming to the ETSI TS 119 411-8 certificate profile, together with the
// Access CA that signs them.
//
// A WRPAC authenticates a wallet-relying party — including a PID Provider or an
// Attestation Provider acting in its provider role — towards a Wallet Unit. Per
// ETSI TS 119 472-3 ISS-MDATA-4.2.1-02 an issuer's WRPAC is the signing
// certificate of its OpenID4VCI Issuer Metadata.
//
// References:
//   - ETSI TS 119 411-8 V1.1.1 — Access Certificate Policy for EUDI Wallet WRPs
//   - ETSI EN 319 412-2 — Certificate profiles for natural persons
//   - ETSI EN 319 412-3 — Certificate profiles for legal persons
//   - CIR (EU) 2025/848 Annex IV — access certificate requirements
package wrpac

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
)

// Certificate policy OIDs per ETSI TS 119 411-8 clause GEN-6.6.1-03.
const (
	// PolicyNCPNaturalPerson is the Normalised Certificate Policy, natural person.
	PolicyNCPNaturalPerson = "0.4.0.194118.1.1" // NCP-n-eudiwrp
	// PolicyNCPLegalPerson is the Normalised Certificate Policy, legal person.
	PolicyNCPLegalPerson = "0.4.0.194118.1.2" // NCP-l-eudiwrp
	// PolicyQCPNaturalPerson is the Qualified Certificate Policy, natural person.
	PolicyQCPNaturalPerson = "0.4.0.194118.1.3" // QCP-n-eudiwrp
	// PolicyQCPLegalPerson is the Qualified Certificate Policy, legal person.
	PolicyQCPLegalPerson = "0.4.0.194118.1.4" // QCP-l-eudiwrp
)

// PolicyOIDs is the complete set of WRPAC certificate policy OIDs.
var PolicyOIDs = []string{
	PolicyNCPNaturalPerson,
	PolicyNCPLegalPerson,
	PolicyQCPNaturalPerson,
	PolicyQCPLegalPerson,
}

// Subject attribute OIDs used by the WRPAC profile.
//
// NOTE: ETSI EN 319 412-3 clause 4.2.1 requires organizationIdentifier
// (2.5.4.97) for legal persons. go-trust's rpcert.WRPACProfile.ExtractIdentity
// currently reads Subject.SerialNumber (2.5.4.5) and reports it as
// "organization_identifier". Until that is corrected (plan track A1), issued
// certificates carry the identifier in BOTH attributes so that a
// standards-conformant consumer and the current go-trust extractor agree.
var (
	oidOrganizationIdentifier = asn1.ObjectIdentifier{2, 5, 4, 97}
)

// SubjectKind distinguishes the two WRPAC subject profiles.
type SubjectKind string

const (
	// LegalPerson selects the EN 319 412-3 profile.
	LegalPerson SubjectKind = "legal"
	// NaturalPerson selects the EN 319 412-2 profile.
	NaturalPerson SubjectKind = "natural"
)

// AssuranceLevel selects between the normalised and qualified policy OIDs.
type AssuranceLevel string

const (
	// Normalised selects an NCP policy OID.
	Normalised AssuranceLevel = "ncp"
	// Qualified selects a QCP policy OID.
	Qualified AssuranceLevel = "qcp"
)

// PolicyOIDFor returns the WRPAC certificate policy OID for a subject kind and
// assurance level.
func PolicyOIDFor(kind SubjectKind, level AssuranceLevel) (string, error) {
	switch {
	case kind == LegalPerson && level == Normalised:
		return PolicyNCPLegalPerson, nil
	case kind == LegalPerson && level == Qualified:
		return PolicyQCPLegalPerson, nil
	case kind == NaturalPerson && level == Normalised:
		return PolicyNCPNaturalPerson, nil
	case kind == NaturalPerson && level == Qualified:
		return PolicyQCPNaturalPerson, nil
	default:
		return "", fmt.Errorf("wrpac: no policy OID for kind=%q level=%q", kind, level)
	}
}

// Validate applies the same checks go-trust's rpcert.WRPACProfile.ValidateCredential
// applies, so that `siros-wrpac-tool verify` and the trust engine agree on what a
// conformant WRPAC is.
//
// Beyond chain verification a WRPAC must:
//   - have keyUsage including nonRepudiation (contentCommitment)
//   - carry a subjectAltName with at least one URI or email contact
//   - assert at least one WRPAC certificate policy OID
func Validate(cert *x509.Certificate) error {
	if cert.KeyUsage&x509.KeyUsageContentCommitment == 0 {
		return fmt.Errorf("wrpac: keyUsage does not include nonRepudiation (contentCommitment)")
	}
	if len(cert.URIs) == 0 && len(cert.EmailAddresses) == 0 {
		return fmt.Errorf("wrpac: subjectAltName missing contact information (URI or email)")
	}
	for _, oid := range cert.Policies {
		for _, want := range PolicyOIDs {
			if oid.String() == want {
				return nil
			}
		}
	}
	return fmt.Errorf("wrpac: no WRPAC policy OID present (expected one of %v)", PolicyOIDs)
}
