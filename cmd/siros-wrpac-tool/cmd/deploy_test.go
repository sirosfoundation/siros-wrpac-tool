package cmd

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
	"time"

	"github.com/sirosfoundation/siros-wrpac-tool/pkg/store"
	"github.com/sirosfoundation/siros-wrpac-tool/pkg/wrprc"
)

// newDeployment initialises a deployment in a temp dir and points the shared
// command flags at it. The commands read package-level option structs, so each
// test resets them rather than inheriting another test's values.
func newDeployment(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "deployment")
	deployDir = dir

	initOpts.baseURL = "https://r.test"
	initOpts.caName = "Test Access CA"
	initOpts.regName = "Test Registrar"
	initOpts.org = "SIROS Foundation"
	initOpts.country = "SE"
	initOpts.validity = 10 * 365 * 24 * time.Hour
	initOpts.pkcs11Module = ""
	initOpts.caKeyLabel = ""
	initOpts.regKeyLabel = ""

	if err := runInit(nil, nil); err != nil {
		t.Fatalf("init: %v", err)
	}
	return dir
}

func resetIssueOpts() {
	issueOpts.name = ""
	issueOpts.organization = ""
	issueOpts.identifier = ""
	issueOpts.country = "SE"
	issueOpts.supportURI = ""
	issueOpts.email = ""
	issueOpts.entitlements = []string{wrprc.EntitlementServiceProvider}
	issueOpts.vct = nil
	issueOpts.doctype = nil
	issueOpts.validity = 365 * 24 * time.Hour
	issueOpts.natural = false
	issueOpts.qualified = false
	issueOpts.out = ""
}

func TestInitCreatesBothTrustServices(t *testing.T) {
	dir := newDeployment(t)

	for _, name := range []string{"ca.pem", "ca.key", "registrar.pem", "registrar.key", "register.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s missing: %v", name, err)
		}
	}
	// The CA and registrar must be distinct trust services, not one key twice.
	ca, err := store.ReadCert(filepath.Join(dir, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	reg, err := store.ReadCert(filepath.Join(dir, "registrar.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if ca.Equal(reg) {
		t.Error("the registrar reused the CA certificate")
	}
	// Publishing happens on init so a fresh deployment already says "nothing revoked".
	if _, err := os.Stat(filepath.Join(dir, "public", "crl.der")); err != nil {
		t.Errorf("CRL not published on init: %v", err)
	}
}

func TestInitRefusesToRunTwice(t *testing.T) {
	newDeployment(t)
	if err := runInit(nil, nil); err == nil {
		t.Fatal("expected re-initialising to be refused — it would replace the CA key")
	}
}

func TestInitRequiresKeyLabelsWithPKCS11(t *testing.T) {
	deployDir = filepath.Join(t.TempDir(), "deployment")
	initOpts.baseURL = "https://r.test"
	initOpts.pkcs11Module = "/nonexistent.so"
	initOpts.caKeyLabel = ""
	initOpts.regKeyLabel = ""
	defer func() { initOpts.pkcs11Module = "" }()

	if err := runInit(nil, nil); err == nil {
		t.Fatal("expected --pkcs11-module without key labels to fail")
	}
}

func TestIssueRegistersAndMintsBothCertificates(t *testing.T) {
	dir := newDeployment(t)
	resetIssueOpts()
	issueOpts.name = "Acme PID"
	issueOpts.organization = "Acme AB"
	issueOpts.identifier = "LEIXG-ACME1"
	issueOpts.supportURI = "https://acme.test/support"
	issueOpts.entitlements = []string{wrprc.EntitlementPIDProvider}
	issueOpts.vct = []string{"urn:eudi:pid:1"}
	issueOpts.out = filepath.Join(t.TempDir(), "out")

	if err := runIssue(nil, nil); err != nil {
		t.Fatalf("issue: %v", err)
	}
	for _, f := range []string{"wrpac.pem", "wrpac.key", "wrprc.jwt"} {
		if _, err := os.Stat(filepath.Join(issueOpts.out, f)); err != nil {
			t.Errorf("%s missing: %v", f, err)
		}
	}

	s, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Register.Entries) != 1 {
		t.Fatalf("register has %d entries, want 1", len(s.Register.Entries))
	}
	for _, e := range s.Register.Entries {
		if e.Identifier != "LEIXG-ACME1" {
			t.Errorf("identifier = %q", e.Identifier)
		}
	}
}

func TestIssueRequiresAContact(t *testing.T) {
	newDeployment(t)
	resetIssueOpts()
	issueOpts.name = "No Contact"
	issueOpts.organization = "NC AB"
	issueOpts.identifier = "LEIXG-NC1"

	if err := runIssue(nil, nil); err == nil {
		t.Fatal("expected issuing without a contact to fail")
	}
}

// Revoking must drive both mechanisms: the CRL and the status list. Revoking one
// alone leaves the party usable through the other.
func TestRevokeDrivesCRLAndStatusList(t *testing.T) {
	dir := newDeployment(t)
	resetIssueOpts()
	issueOpts.name = "Acme"
	issueOpts.organization = "Acme AB"
	issueOpts.identifier = "LEIXG-ACME2"
	issueOpts.supportURI = "https://acme.test/support"
	issueOpts.out = filepath.Join(t.TempDir(), "out")
	if err := runIssue(nil, nil); err != nil {
		t.Fatal(err)
	}

	s, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	var serial string
	for k := range s.Register.Entries {
		serial = k
	}

	if err := runRevoke(nil, []string{serial}); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	crlRaw, err := os.ReadFile(filepath.Join(dir, "public", "crl.der"))
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseRevocationList(crlRaw)
	if err != nil {
		t.Fatal(err)
	}
	if len(crl.RevokedCertificateEntries) != 1 {
		t.Errorf("CRL has %d entries, want 1", len(crl.RevokedCertificateEntries))
	}

	reopened, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !reopened.Register.Entries[serial].Revoked {
		t.Error("entry is not marked revoked")
	}
}

func TestRevokeUnknownSerialFails(t *testing.T) {
	newDeployment(t)
	if err := runRevoke(nil, []string{"deadbeef"}); err == nil {
		t.Fatal("expected revoking an unknown serial to fail")
	}
}

func TestRevokeIsIdempotent(t *testing.T) {
	dir := newDeployment(t)
	resetIssueOpts()
	issueOpts.name = "Acme"
	issueOpts.organization = "Acme AB"
	issueOpts.identifier = "LEIXG-ACME3"
	issueOpts.supportURI = "https://acme.test/support"
	issueOpts.out = filepath.Join(t.TempDir(), "out")
	if err := runIssue(nil, nil); err != nil {
		t.Fatal(err)
	}
	s, _ := store.Open(dir)
	var serial string
	for k := range s.Register.Entries {
		serial = k
	}
	if err := runRevoke(nil, []string{serial}); err != nil {
		t.Fatal(err)
	}
	if err := runRevoke(nil, []string{serial}); err != nil {
		t.Errorf("revoking twice should be a no-op, got: %v", err)
	}
}

func TestListAndPublishOnAnEmptyDeployment(t *testing.T) {
	newDeployment(t)
	if err := listCmd.RunE(nil, nil); err != nil {
		t.Errorf("list: %v", err)
	}
	if err := publishCmd.RunE(nil, nil); err != nil {
		t.Errorf("publish: %v", err)
	}
}

func TestCommandsRejectAnUninitialisedDirectory(t *testing.T) {
	deployDir = filepath.Join(t.TempDir(), "missing")
	if err := listCmd.RunE(nil, nil); err == nil {
		t.Error("expected list to fail on an uninitialised deployment")
	}
	resetIssueOpts()
	issueOpts.name = "X"
	issueOpts.organization = "X AB"
	issueOpts.identifier = "LEIXG-X"
	issueOpts.supportURI = "https://x/s"
	if err := runIssue(nil, nil); err == nil {
		t.Error("expected issue to fail on an uninitialised deployment")
	}
}

func TestLoTEPublishesSignedAndUnsigned(t *testing.T) {
	dir := newDeployment(t)
	loteOpts.out = ""
	loteOpts.sequence = 0
	loteOpts.territory = "SE"
	loteOpts.operator = "SIROS Foundation"
	loteOpts.schemeName = "Test"
	loteOpts.distribution = ""
	loteOpts.nextUpdate = 90 * 24 * time.Hour
	loteOpts.sign = true

	if err := runLoTE(nil, nil); err != nil {
		t.Fatalf("lote: %v", err)
	}
	for _, f := range []string{"lote.json", "lote.json.jws"} {
		if _, err := os.Stat(filepath.Join(dir, "public", f)); err != nil {
			t.Errorf("%s missing: %v", f, err)
		}
	}
}

func TestLoTEUnsigned(t *testing.T) {
	dir := newDeployment(t)
	loteOpts.sign = false
	loteOpts.out = ""
	loteOpts.territory = "SE"
	loteOpts.nextUpdate = 90 * 24 * time.Hour
	defer func() { loteOpts.sign = true }()

	if err := runLoTE(nil, nil); err != nil {
		t.Fatalf("lote: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "public", "lote.json.jws")); err == nil {
		t.Error("a .jws should not be written when --sign=false")
	}
}

func TestSandboxEmitsACompleteSet(t *testing.T) {
	out := filepath.Join(t.TempDir(), "sandbox")
	sandboxOpts.outDir = out
	sandboxOpts.baseURL = "https://issuer.test"
	sandboxOpts.issuerName = "Example Provider"
	sandboxOpts.issuerOrg = "Example GmbH"
	sandboxOpts.identifier = "LEIXG-SANDBOX"
	sandboxOpts.country = "DE"
	sandboxOpts.entitlement = wrprc.EntitlementPIDProvider
	sandboxOpts.vct = "urn:eudi:pid:1"
	sandboxOpts.docType = "eu.europa.ec.eudi.pid.1"

	if err := runSandbox(nil, nil); err != nil {
		t.Fatalf("sandbox: %v", err)
	}
	for _, f := range []string{"ca.pem", "ca.key", "wrpac.pem", "wrpac.key", "crl.der", "registrar.pem", "wrprc.jwt"} {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Errorf("%s missing: %v", f, err)
		}
	}
}

func TestEntitlementsCommandLists(t *testing.T) {
	// Run purely for coverage of the listing; it takes no input and cannot fail.
	entitlementsCmd.Run(nil, nil)
}

func TestVersionCommandRuns(t *testing.T) {
	versionCmd.Run(nil, nil)
}

// writeCSR emits a CSR for the apply tests.
func writeCSR(t *testing.T, dir, name string) {
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
}
