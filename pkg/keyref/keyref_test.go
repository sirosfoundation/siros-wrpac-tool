package keyref

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeKey(t *testing.T, dir string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "k.key")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestResolveFileKey(t *testing.T) {
	path := writeKey(t, t.TempDir())
	ref := Ref{File: path}
	if ref.IsPKCS11() {
		t.Error("a file ref must not report itself as PKCS#11")
	}

	resolved, err := ref.Resolve()
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if resolved.Signer == nil {
		t.Fatal("no signer returned")
	}
	// Close is a no-op for file keys so callers can always defer it.
	if err := resolved.Close(); err != nil {
		t.Errorf("Close on a file key should be a no-op, got: %v", err)
	}
}

func TestResolveRejectsAnEmptyRef(t *testing.T) {
	if _, err := (Ref{}).Resolve(); err == nil {
		t.Fatal("expected an empty reference to fail")
	}
}

func TestResolveFileKeyErrors(t *testing.T) {
	dir := t.TempDir()

	if _, err := (Ref{File: filepath.Join(dir, "missing.key")}).Resolve(); err == nil {
		t.Error("expected a missing file to fail")
	}

	notPEM := filepath.Join(dir, "junk.key")
	if err := os.WriteFile(notPEM, []byte("nonsense"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (Ref{File: notPEM}).Resolve(); err == nil {
		t.Error("expected non-PEM input to fail")
	}

	// A PEM block that is not a PKCS#8 key must be rejected rather than panicking.
	badDER := filepath.Join(dir, "bad.key")
	if err := os.WriteFile(badDER, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}}), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (Ref{File: badDER}).Resolve(); err == nil {
		t.Error("expected a malformed key to fail")
	}
}

// Describe feeds logs and terminal output. It must be useful and must never
// carry a secret — the file form has no PIN, but the shape is shared.
func TestDescribeFileRef(t *testing.T) {
	got := Ref{File: "/deployment/ca.key"}.Describe()
	if !strings.Contains(got, "/deployment/ca.key") {
		t.Errorf("Describe = %q, want it to name the file", got)
	}
	if !strings.HasPrefix(got, "file ") {
		t.Errorf("Describe = %q, want it to say which kind of reference this is", got)
	}
}

func TestDescribePKCS11FallsBackToSlot(t *testing.T) {
	got := Ref{PKCS11: &PKCS11{Module: "/m.so", SlotID: 3, KeyLabel: "ca"}}.Describe()
	for _, want := range []string{"pkcs11", "ca", "slot 3", "/m.so"} {
		if !strings.Contains(got, want) {
			t.Errorf("Describe = %q, want it to contain %q", got, want)
		}
	}
}

func TestPKCS11RefReportsItself(t *testing.T) {
	ref := Ref{PKCS11: &PKCS11{Module: "/m.so", KeyLabel: "ca"}}
	if !ref.IsPKCS11() {
		t.Error("a PKCS#11 ref must report itself as such")
	}
}

// The PIN is never persisted, so resolving without the environment variable set
// must say which variable to set rather than trying an empty PIN.
func TestPKCS11MissingPINNamesTheVariable(t *testing.T) {
	t.Setenv("SIROS_WRPAC_PKCS11_PIN", "")
	if err := os.Unsetenv("SIROS_WRPAC_PKCS11_PIN"); err != nil {
		t.Fatal(err)
	}
	ref := Ref{PKCS11: &PKCS11{Module: "/m.so", KeyLabel: "ca"}}
	_, err := ref.Resolve()
	if err == nil {
		t.Fatal("expected a missing PIN to fail")
	}
	if !strings.Contains(err.Error(), "SIROS_WRPAC_PKCS11_PIN") {
		t.Errorf("error should name the default PIN variable, got: %v", err)
	}
}

func TestPKCS11ValidatesModuleAndLabel(t *testing.T) {
	t.Setenv("SIROS_WRPAC_PKCS11_PIN", "1234")

	if _, err := (Ref{PKCS11: &PKCS11{KeyLabel: "ca"}}).Resolve(); err == nil {
		t.Error("expected a missing module to fail")
	}
	if _, err := (Ref{PKCS11: &PKCS11{Module: "/m.so"}}).Resolve(); err == nil {
		t.Error("expected a missing key label to fail")
	}
}
