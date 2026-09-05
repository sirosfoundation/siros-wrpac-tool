package store

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sirosfoundation/siros-wrpac-tool/pkg/keyref"
)

func TestCreateRefusesToClobberAnExistingDeployment(t *testing.T) {
	dir := t.TempDir()
	if _, err := Create(dir, "https://r.test"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Re-initialising would replace the CA key and silently invalidate every
	// certificate already issued from it.
	if _, err := Create(dir, "https://r.test"); err == nil {
		t.Fatal("expected re-initialisation to be refused")
	}
}

func TestOpenRejectsAnUninitialisedDirectory(t *testing.T) {
	if _, err := Open(t.TempDir()); err == nil {
		t.Fatal("expected opening an uninitialised directory to fail")
	}
}

func TestStatusIndicesAreNeverReused(t *testing.T) {
	s, err := Create(t.TempDir(), "https://r.test")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[int]bool{}
	for i := 0; i < 5; i++ {
		idx := s.AllocateStatusIndex()
		if seen[idx] {
			t.Fatalf("status index %d was allocated twice", idx)
		}
		seen[idx] = true
	}
}

func TestCRLNumberIsMonotonicAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	s, err := Create(dir, "https://r.test")
	if err != nil {
		t.Fatal(err)
	}
	s.NextCRLNumber()
	s.NextCRLNumber()
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}

	// RFC 5280 requires the CRL number to increase. A deployment that restarted
	// and began again at 1 would have its CRLs ignored as stale.
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := reopened.NextCRLNumber(); got != 3 {
		t.Errorf("CRL number after reopen = %d, want 3", got)
	}
}

func TestRegisterSurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	s, err := Create(dir, "https://r.test")
	if err != nil {
		t.Fatal(err)
	}
	s.Register.Entries["abc"] = &Entry{Serial: "abc", Identifier: "LEIXG-1", Name: "P"}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	e, ok := reopened.Register.Entries["abc"]
	if !ok {
		t.Fatal("entry did not survive reopen")
	}
	if e.Identifier != "LEIXG-1" {
		t.Errorf("identifier = %q, want LEIXG-1", e.Identifier)
	}
}

func TestPathsStayInsideTheDeployment(t *testing.T) {
	s := &Store{Dir: "/tmp/dep"}
	if got := s.IssuedPath("ff"); got != filepath.Join("/tmp/dep", "issued", "ff.pem") {
		t.Errorf("IssuedPath = %q", got)
	}
}

func TestWriteAndReadCertRoundTrip(t *testing.T) {
	dir := t.TempDir()
	cert, _ := testCertAndKey(t)
	path := filepath.Join(dir, "c.pem")
	if err := WriteCert(path, cert); err != nil {
		t.Fatalf("WriteCert: %v", err)
	}
	got, err := ReadCert(path)
	if err != nil {
		t.Fatalf("ReadCert: %v", err)
	}
	if !got.Equal(cert) {
		t.Error("certificate did not survive the round trip")
	}
}

// Private keys must never be group- or world-readable, whatever the umask.
func TestWriteKeyIsOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	_, key := testCertAndKey(t)
	path := filepath.Join(dir, "k.key")
	if err := WriteKey(path, key); err != nil {
		t.Fatalf("WriteKey: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key mode = %o, want 600", perm)
	}
	got, err := ReadKey(path)
	if err != nil {
		t.Fatalf("ReadKey: %v", err)
	}
	if !got.Equal(key) {
		t.Error("key did not survive the round trip")
	}
}

func TestReadRejectsMissingAndMalformedFiles(t *testing.T) {
	dir := t.TempDir()
	if _, err := ReadCert(filepath.Join(dir, "nope.pem")); err == nil {
		t.Error("expected a missing certificate to fail")
	}
	if _, err := ReadKey(filepath.Join(dir, "nope.key")); err == nil {
		t.Error("expected a missing key to fail")
	}

	notPEM := filepath.Join(dir, "junk.pem")
	if err := os.WriteFile(notPEM, []byte("not pem at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadCert(notPEM); err == nil {
		t.Error("expected non-PEM input to fail")
	}
	if _, err := ReadKey(notPEM); err == nil {
		t.Error("expected non-PEM input to fail")
	}
}

func TestKeyRefsDefaultToTheOnDiskLayout(t *testing.T) {
	s, err := Create(t.TempDir(), "https://r.test")
	if err != nil {
		t.Fatal(err)
	}
	if got := s.CAKeyRef(); got.File != s.CAKeyPath() {
		t.Errorf("CA key ref = %v, want the on-disk default", got)
	}
	if got := s.RegistrarKeyRef(); got.File != s.RegistrarKeyPath() {
		t.Errorf("registrar key ref = %v, want the on-disk default", got)
	}

	s.Register.CAKey = keyref.Ref{PKCS11: &keyref.PKCS11{Module: "m", KeyLabel: "ca"}}
	if !s.CAKeyRef().IsPKCS11() {
		t.Error("a configured PKCS#11 ref should win over the default")
	}
}

func TestActiveByClientSkipsSupersededEntries(t *testing.T) {
	s, err := Create(t.TempDir(), "https://r.test")
	if err != nil {
		t.Fatal(err)
	}
	s.Register.Entries["old"] = &Entry{Serial: "old", ClientID: "acme", Superseded: true}
	s.Register.Entries["new"] = &Entry{Serial: "new", ClientID: "acme"}

	got := s.ActiveByClient("acme")
	if got == nil || got.Serial != "new" {
		t.Errorf("ActiveByClient returned %v, want the non-superseded entry", got)
	}
	if s.ActiveByClient("unknown") != nil {
		t.Error("expected nil for an unknown client")
	}
}

func testCertAndKey(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "Store Test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
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

func TestValiditiesDefaultAndParse(t *testing.T) {
	s, err := Create(filepath.Join(t.TempDir(), "d"), "https://r.test")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []func() (time.Duration, error){s.CRLValidityDuration, s.StatusListValidityDuration} {
		d, err := f()
		if err != nil || d != DefaultRevocationValidity {
			t.Errorf("empty setting: got %s, %v; want default", d, err)
		}
	}
	s.Register.CRLValidity = "48h"
	s.Register.StatusListValidity = "72h"
	if d, err := s.CRLValidityDuration(); err != nil || d != 48*time.Hour {
		t.Errorf("crl: got %s, %v", d, err)
	}
	if d, err := s.StatusListValidityDuration(); err != nil || d != 72*time.Hour {
		t.Errorf("status list: got %s, %v", d, err)
	}
	for _, bad := range []string{"soon", "-1h", "0s"} {
		s.Register.StatusListValidity = bad
		if _, err := s.StatusListValidityDuration(); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}
