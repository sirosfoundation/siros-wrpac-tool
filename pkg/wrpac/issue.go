package wrpac

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"net/url"
	"time"
)

// Request describes a WRPAC to be issued.
type Request struct {
	Kind  SubjectKind
	Level AssuranceLevel

	// CommonName is the WRP's trade name (EN 319 412-3 clause 4.2.1).
	CommonName string
	// Organization is the WRP's registered legal name. Required for LegalPerson.
	Organization string
	// GivenName and Surname apply to NaturalPerson subjects.
	GivenName string
	Surname   string
	// Country is the ISO 3166-1 alpha-2 code of establishment.
	Country string
	// Identifier is the EU-wide unique WRP identifier in the semantic form of
	// ETSI EN 319 412-1 clause 5.1.4, e.g. "LEIXG-529900T8BM49AURSDO55".
	Identifier string

	// SupportURI and Email populate subjectAltName. At least one is required:
	// go-trust rejects a WRPAC with no contact method.
	SupportURI string
	Email      string

	Validity time.Duration
}

// Issued is a freshly minted WRPAC and its private key.
type Issued struct {
	Certificate *x509.Certificate
	Key         crypto.Signer
}

// Issue mints a WRPAC signed by the CA.
func (c *CA) Issue(req Request) (*Issued, error) {
	if req.CommonName == "" {
		return nil, fmt.Errorf("wrpac: common name is required")
	}
	if req.Identifier == "" {
		return nil, fmt.Errorf("wrpac: identifier is required")
	}
	if req.SupportURI == "" && req.Email == "" {
		return nil, fmt.Errorf("wrpac: a support URI or email is required (subjectAltName must carry a contact)")
	}
	if req.Kind == LegalPerson && req.Organization == "" {
		return nil, fmt.Errorf("wrpac: organization is required for a legal person")
	}
	if req.Validity == 0 {
		req.Validity = 365 * 24 * time.Hour
	}

	policyOID, err := PolicyOIDFor(req.Kind, req.Level)
	if err != nil {
		return nil, err
	}
	oid, err := x509.ParseOID(policyOID)
	if err != nil {
		return nil, fmt.Errorf("wrpac: parse policy OID %q: %w", policyOID, err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("wrpac: generate key: %w", err)
	}
	serial, err := serialNumber()
	if err != nil {
		return nil, err
	}

	subject := pkix.Name{
		CommonName: req.CommonName,
		Country:    nonEmpty(req.Country),
		// See the note on oidOrganizationIdentifier: the identifier is written
		// to serialNumber (2.5.4.5) as well as organizationIdentifier (2.5.4.97)
		// so both the standards-conformant reading and go-trust's current
		// extractor resolve the same value.
		SerialNumber: req.Identifier,
		ExtraNames: []pkix.AttributeTypeAndValue{
			{Type: oidOrganizationIdentifier, Value: req.Identifier},
		},
	}
	switch req.Kind {
	case LegalPerson:
		subject.Organization = nonEmpty(req.Organization)
	case NaturalPerson:
		if req.GivenName != "" {
			subject.ExtraNames = append(subject.ExtraNames,
				pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 42}, Value: req.GivenName})
		}
		if req.Surname != "" {
			subject.ExtraNames = append(subject.ExtraNames,
				pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 4}, Value: req.Surname})
		}
	}

	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      subject,
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(req.Validity),
		// nonRepudiation is mandatory. It is deliberately not exclusive: the
		// same certificate may also carry digitalSignature, which is what lets
		// one WRPAC serve both request signing and metadata signing.
		KeyUsage:              x509.KeyUsageContentCommitment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		Policies:              []x509.OID{oid},
		EmailAddresses:        nonEmpty(req.Email),
	}
	if req.SupportURI != "" {
		u, err := url.Parse(req.SupportURI)
		if err != nil {
			return nil, fmt.Errorf("wrpac: parse support URI: %w", err)
		}
		tmpl.URIs = []*url.URL{u}
	}
	if c.CRLDistributionPoint != "" {
		tmpl.CRLDistributionPoints = []string{c.CRLDistributionPoint}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.Certificate, key.Public(), c.Key)
	if err != nil {
		return nil, fmt.Errorf("wrpac: create certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("wrpac: parse issued certificate: %w", err)
	}
	if err := Validate(cert); err != nil {
		return nil, fmt.Errorf("wrpac: issued certificate fails its own profile check: %w", err)
	}
	return &Issued{Certificate: cert, Key: key}, nil
}
