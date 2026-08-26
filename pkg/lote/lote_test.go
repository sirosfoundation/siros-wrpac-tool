package lote

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testCert(t *testing.T, cn string) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func testEntities(t *testing.T) []Entity {
	t.Helper()
	ca, _ := testCert(t, "Test Access CA")
	reg, _ := testCert(t, "Test Registrar")
	return []Entity{
		{Name: "Test Access CA", ServiceType: ServiceTypeAccessCA, Certificate: ca,
			InformationURI: "https://r.test", ElectronicAddress: "https://r.test/support"},
		{Name: "Test Registrar", ServiceType: ServiceTypeRegistrationCertProvider, Certificate: reg,
			InformationURI: "https://r.test/registrar", ElectronicAddress: "https://r.test/support"},
	}
}

func testOptions() Options {
	return Options{
		SequenceNumber:    3,
		Territory:         "SE",
		OperatorName:      "SIROS Foundation",
		SchemeName:        "Test scheme",
		DistributionPoint: "https://r.test/lote.json",
		InformationURI:    "https://r.test",
	}
}

func TestBuildProducesAValidLoTE(t *testing.T) {
	list, err := Build(testEntities(t), testOptions())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if got := len(list.TrustedEntitiesList); got != 2 {
		t.Fatalf("entities = %d, want 2", got)
	}
	info := list.ListAndSchemeInformation
	if info.LoTESequenceNumber != 3 {
		t.Errorf("sequence = %d, want 3", info.LoTESequenceNumber)
	}
	if info.SchemeTerritory != "SE" {
		t.Errorf("territory = %q", info.SchemeTerritory)
	}
	if info.NextUpdate == "" {
		t.Error("NextUpdate must be set — consumers need to know when to refetch")
	}
}

// Outside the PuB-EAA profile, LoTE treats presence in the list as the trust
// statement; a ServiceStatus there is rejected by the schema.
func TestBuildOmitsServiceStatus(t *testing.T) {
	list, err := Build(testEntities(t), testOptions())
	if err != nil {
		t.Fatal(err)
	}
	for i, te := range list.TrustedEntitiesList {
		if got := te.TrustedEntityServices[0].ServiceInformation.ServiceStatus; got != "" {
			t.Errorf("entity %d has ServiceStatus %q, want it absent", i, got)
		}
	}
}

func TestBuildCarriesTheCertificate(t *testing.T) {
	entities := testEntities(t)
	list, err := Build(entities, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	certs := list.TrustedEntitiesList[0].TrustedEntityServices[0].ServiceInformation.ServiceDigitalIdentity.X509Certificates
	if len(certs) != 1 {
		t.Fatalf("want one certificate, got %d", len(certs))
	}
	if certs[0].Val == "" {
		t.Error("certificate value is empty")
	}
}

func TestBuildRejectsEmptyAndCertlessEntities(t *testing.T) {
	if _, err := Build(nil, testOptions()); err == nil {
		t.Error("expected an empty entity list to be rejected")
	}
	if _, err := Build([]Entity{{Name: "No cert"}}, testOptions()); err == nil {
		t.Error("expected an entity with no certificate to be rejected")
	}
}

// The filename must match g119612's publish-lote naming, or output from this
// tool and from a tsl-tool pipeline land on different files.
func TestFilenameFollowsTheDistributionPoint(t *testing.T) {
	list, err := Build(testEntities(t), testOptions())
	if err != nil {
		t.Fatal(err)
	}
	if got := Filename(list); got != "lote.json" {
		t.Errorf("Filename = %q, want lote.json", got)
	}

	opts := testOptions()
	opts.DistributionPoint = "https://r.test/lists/trust-anchors.json"
	list, err = Build(testEntities(t), opts)
	if err != nil {
		t.Fatal(err)
	}
	if got := Filename(list); got != "trust-anchors.json" {
		t.Errorf("Filename = %q, want trust-anchors.json", got)
	}
}

func TestFilenameFallsBackToTerritory(t *testing.T) {
	opts := testOptions()
	opts.DistributionPoint = ""
	list, err := Build(testEntities(t), opts)
	if err != nil {
		t.Fatal(err)
	}
	if got := Filename(list); got != "lote-SE.json" {
		t.Errorf("Filename = %q, want lote-SE.json", got)
	}
}

func TestPublishWritesUnsignedJSON(t *testing.T) {
	list, err := Build(testEntities(t), testOptions())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	written, err := Publish(list, dir, nil)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if len(written) != 1 {
		t.Fatalf("wrote %d files, want 1 without a signer", len(written))
	}
	raw, err := os.ReadFile(filepath.Join(dir, "lote.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
}

// Signing writes the detached JWS *and* keeps the unsigned JSON, because that
// is what publish-lote does and a pipeline reading the directory expects both.
func TestPublishSignedWritesBothFiles(t *testing.T) {
	entities := testEntities(t)
	list, err := Build(entities, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	cert, key := testCert(t, "Signer")
	signer, err := KeySigner(key, []*x509.Certificate{cert})
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	written, err := Publish(list, dir, signer)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if len(written) != 2 {
		t.Fatalf("wrote %d files, want the JSON and its .jws", len(written))
	}
	tok, err := os.ReadFile(filepath.Join(dir, "lote.json.jws"))
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(strings.TrimSpace(string(tok)), "."); n != 2 {
		t.Errorf("signature is not a compact JWS: %d dots", n)
	}
	if _, err := os.Stat(filepath.Join(dir, "lote.json")); err != nil {
		t.Errorf("unsigned JSON missing: %v", err)
	}
}

func TestKeySignerRequiresKeyAndChain(t *testing.T) {
	cert, key := testCert(t, "Signer")
	if _, err := KeySigner(nil, []*x509.Certificate{cert}); err == nil {
		t.Error("expected a nil key to be rejected")
	}
	if _, err := KeySigner(key, nil); err == nil {
		t.Error("expected an empty chain to be rejected")
	}
}
