package clientspec

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

// writeCSR emits a valid CSR and returns its path.
func writeCSR(t *testing.T, dir, name string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: name}}, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name+".csr")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

const validSpec = `name: Example Provider
organization: Example Provider GmbH
identifier: LEIXG-529900T8BM49AURSDO55
country: DE
support_uri: https://example.org/support
csr: example.csr
entitlements:
  - https://uri.etsi.org/19475/Entitlement/PID_Provider
provides:
  - vct: urn:eudi:pid:1
`

func writeSpec(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name+".yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadFileDefaultsIDToFilename(t *testing.T) {
	dir := t.TempDir()
	writeCSR(t, dir, "example")
	path := writeSpec(t, dir, "example", validSpec)

	spec, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if spec.ID != "example" {
		t.Errorf("ID = %q, want the filename stem", spec.ID)
	}
	if spec.CertificateRequest() == nil {
		t.Error("CSR was not loaded")
	}
}

// A misspelled key must fail rather than be ignored: silently dropping
// "entitlments" would issue a certificate with no entitlements at all.
func TestLoadFileRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	writeCSR(t, dir, "example")
	path := writeSpec(t, dir, "example", validSpec+"entitlments:\n  - typo\n")
	if _, err := LoadFile(path); err == nil {
		t.Fatal("expected an unknown field to be rejected")
	}
}

func TestLoadRejectsDuplicateIDs(t *testing.T) {
	dir := t.TempDir()
	writeCSR(t, dir, "example")
	writeSpec(t, dir, "a", validSpec+"id: same\n")
	writeSpec(t, dir, "b", validSpec+"id: same\n")
	if _, err := Load(dir); err == nil {
		t.Fatal("expected duplicate ids to be rejected")
	}
}

// Proof of possession: a CSR whose signature does not verify must not be
// accepted, or anyone could have a certificate issued over another party's key.
func TestLoadFileRejectsTamperedCSR(t *testing.T) {
	dir := t.TempDir()
	csrPath := writeCSR(t, dir, "example")
	raw, err := os.ReadFile(csrPath)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(raw)
	blk.Bytes[len(blk.Bytes)-1] ^= 0xff // corrupt the signature
	if err := os.WriteFile(csrPath, pem.EncodeToMemory(blk), 0o644); err != nil {
		t.Fatal(err)
	}
	path := writeSpec(t, dir, "example", validSpec)
	if _, err := LoadFile(path); err == nil {
		t.Fatal("expected a CSR failing its own signature check to be rejected")
	}
}

func TestValidateRequiresContactAndOrganization(t *testing.T) {
	base := Spec{
		ID: "x", Name: "X", Identifier: "LEIXG-1", Country: "SE",
		Entitlements: []string{"e"}, CSR: "x.csr", Organization: "X AB",
		SupportURI: "https://x/s",
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("valid spec rejected: %v", err)
	}

	noContact := base
	noContact.SupportURI = ""
	if err := noContact.Validate(); err == nil {
		t.Error("expected a spec with no contact to be rejected")
	}

	noOrg := base
	noOrg.Organization = ""
	if err := noOrg.Validate(); err == nil {
		t.Error("expected a legal person with no organization to be rejected")
	}
}

// The fingerprint drives re-issuance, so it must move when the key moves.
func TestFingerprintTracksThePublicKey(t *testing.T) {
	dir := t.TempDir()
	writeCSR(t, dir, "example")
	path := writeSpec(t, dir, "example", validSpec)

	first, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	before := first.Fingerprint()

	writeCSR(t, dir, "example") // client rotates its key
	second, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if second.Fingerprint() == before {
		t.Error("fingerprint did not change when the CSR public key changed")
	}
}

func TestFingerprintIgnoresEntitlementOrderAndRevoked(t *testing.T) {
	a := Spec{Name: "X", Entitlements: []string{"one", "two"}}
	b := Spec{Name: "X", Entitlements: []string{"two", "one"}}
	if a.Fingerprint() != b.Fingerprint() {
		t.Error("entitlement order should not affect the fingerprint")
	}

	// Revocation is its own transition, not a reason to re-issue.
	c := a
	c.Revoked = true
	if c.Fingerprint() != a.Fingerprint() {
		t.Error("revoked should not affect the fingerprint")
	}
}

func TestValidityDefaultsToOneYear(t *testing.T) {
	s := Spec{}
	d, err := s.ValidityDuration()
	if err != nil {
		t.Fatal(err)
	}
	if d.Hours() != 365*24 {
		t.Errorf("default validity = %v, want a year", d)
	}
	bad := Spec{ID: "x", Validity: "nonsense"}
	if _, err := bad.ValidityDuration(); err == nil {
		t.Error("expected an unparseable validity to be rejected")
	}
}
