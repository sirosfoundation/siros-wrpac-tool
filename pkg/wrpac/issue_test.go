package wrpac

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
	"time"
)

func testCA(t *testing.T) *CA {
	t.Helper()
	ca, err := NewCA(CAOptions{CommonName: "Test Access CA", Country: "SE", CRLDistributionPoint: "https://ca.example/crl"})
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	return ca
}

func legalRequest() Request {
	return Request{
		Kind:         LegalPerson,
		Level:        Normalised,
		CommonName:   "Example Provider",
		Organization: "Example Provider AB",
		Country:      "SE",
		Identifier:   "LEIXG-529900T8BM49AURSDO55",
		SupportURI:   "https://example.org/support",
	}
}

func TestIssueProducesConformantWRPAC(t *testing.T) {
	ca := testCA(t)
	issued, err := ca.Issue(legalRequest())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if err := Validate(issued.Certificate); err != nil {
		t.Errorf("issued certificate is not conformant: %v", err)
	}
	if issued.Certificate.KeyUsage&x509.KeyUsageContentCommitment == 0 {
		t.Error("keyUsage is missing nonRepudiation")
	}
	// EN 319 412-3 puts the identifier in organizationIdentifier (2.5.4.97).
	// It must not also appear in serialNumber: duplicating it was a workaround
	// for a go-trust extractor bug fixed in v0.20.0, and leaving it would keep
	// two sources of truth for the same value.
	if got := subjectAttr(issued.Certificate, oidOrganizationIdentifier); got != legalRequest().Identifier {
		t.Errorf("organizationIdentifier = %q, want the WRP identifier", got)
	}
	if got := issued.Certificate.Subject.SerialNumber; got != "" {
		t.Errorf("serialNumber = %q, want it empty — the identifier belongs in organizationIdentifier", got)
	}
	// The certificate must chain to the CA that issued it.
	pool := x509.NewCertPool()
	pool.AddCert(ca.Certificate)
	if _, err := issued.Certificate.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		t.Errorf("chain verification failed: %v", err)
	}
}

// subjectAttr returns the value of a subject attribute by OID, reading the raw
// RDN sequence because crypto/x509 does not surface non-standard attributes.
func subjectAttr(cert *x509.Certificate, oid asn1.ObjectIdentifier) string {
	var rdns pkix.RDNSequence
	if _, err := asn1.Unmarshal(cert.RawSubject, &rdns); err != nil {
		return ""
	}
	for _, rdn := range rdns {
		for _, atv := range rdn {
			if atv.Type.Equal(oid) {
				if s, ok := atv.Value.(string); ok {
					return s
				}
			}
		}
	}
	return ""
}

func TestIssueRequiresContactInSAN(t *testing.T) {
	ca := testCA(t)
	req := legalRequest()
	req.SupportURI = ""
	req.Email = ""
	if _, err := ca.Issue(req); err == nil {
		t.Fatal("expected an error when no contact method is supplied")
	}
}

func TestIssueRequiresOrganizationForLegalPerson(t *testing.T) {
	ca := testCA(t)
	req := legalRequest()
	req.Organization = ""
	if _, err := ca.Issue(req); err == nil {
		t.Fatal("expected an error when a legal person has no organization")
	}
}

func TestPolicyOIDSelection(t *testing.T) {
	cases := []struct {
		kind  SubjectKind
		level AssuranceLevel
		want  string
	}{
		{LegalPerson, Normalised, PolicyNCPLegalPerson},
		{LegalPerson, Qualified, PolicyQCPLegalPerson},
		{NaturalPerson, Normalised, PolicyNCPNaturalPerson},
		{NaturalPerson, Qualified, PolicyQCPNaturalPerson},
	}
	for _, c := range cases {
		got, err := PolicyOIDFor(c.kind, c.level)
		if err != nil {
			t.Errorf("PolicyOIDFor(%s,%s): %v", c.kind, c.level, err)
			continue
		}
		if got != c.want {
			t.Errorf("PolicyOIDFor(%s,%s) = %s, want %s", c.kind, c.level, got, c.want)
		}
	}
	if _, err := PolicyOIDFor("bogus", Normalised); err == nil {
		t.Error("expected an error for an unknown subject kind")
	}
}

func TestCreateCRLIsPublishableWhenEmpty(t *testing.T) {
	ca := testCA(t)
	der, err := ca.CreateCRL(nil, time.Now().UTC(), 24*time.Hour)
	if err != nil {
		t.Fatalf("CreateCRL: %v", err)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatalf("ParseRevocationList: %v", err)
	}
	if len(crl.RevokedCertificateEntries) != 0 {
		t.Errorf("expected an empty CRL, got %d entries", len(crl.RevokedCertificateEntries))
	}
	if err := crl.CheckSignatureFrom(ca.Certificate); err != nil {
		t.Errorf("CRL signature does not verify against the CA: %v", err)
	}
}
