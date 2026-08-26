//go:build softhsm

package keyref

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"os"
	"testing"
)

func TestResolvePKCS11ReturnsAWorkingSigner(t *testing.T) {
	h := newSoftHSM(t)
	h.generateEC(t, "ca")

	resolved, err := h.ref(t, "ca").Resolve()
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	defer func() { _ = resolved.Close() }()

	pub, ok := resolved.Signer.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("public key is %T, want *ecdsa.PublicKey", resolved.Signer.Public())
	}
	if pub.Curve.Params().Name != "P-256" {
		t.Errorf("curve = %s, want P-256", pub.Curve.Params().Name)
	}

	// The signature must verify against the token's own public key, which is the
	// only proof the private half never left the token and was actually used.
	digest := sha256.Sum256([]byte("wrpac"))
	sig, err := resolved.Signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		t.Error("signature does not verify against the token's public key")
	}
}

func TestResolvePKCS11SigningIsRepeatable(t *testing.T) {
	h := newSoftHSM(t)
	h.generateEC(t, "ca")

	resolved, err := h.ref(t, "ca").Resolve()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resolved.Close() }()

	pub := resolved.Signer.Public().(*ecdsa.PublicKey)
	// Several signatures in a row exercise session checkout and return; a pool
	// that leaked a session would fail here rather than on the first call.
	for i := 0; i < 5; i++ {
		digest := sha256.Sum256([]byte{byte(i)})
		sig, err := resolved.Signer.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			t.Fatalf("Sign %d: %v", i, err)
		}
		if !ecdsa.VerifyASN1(pub, digest[:], sig) {
			t.Fatalf("signature %d does not verify", i)
		}
	}
}

func TestResolvePKCS11DistinctLabelsGiveDistinctKeys(t *testing.T) {
	h := newSoftHSM(t)
	h.generateEC(t, "ca")
	h.generateEC(t, "registrar")

	caResolved, err := h.ref(t, "ca").Resolve()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = caResolved.Close() }()

	regResolved, err := h.ref(t, "registrar").Resolve()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = regResolved.Close() }()

	caPub := caResolved.Signer.Public().(*ecdsa.PublicKey)
	regPub := regResolved.Signer.Public().(*ecdsa.PublicKey)
	if caPub.Equal(regPub) {
		t.Error("the CA and registrar labels resolved to the same key")
	}
}

func TestResolvePKCS11UnknownLabelFails(t *testing.T) {
	h := newSoftHSM(t)
	h.generateEC(t, "ca")

	if _, err := h.ref(t, "does-not-exist").Resolve(); err == nil {
		t.Fatal("expected an unknown key label to fail")
	}
}

// The PIN is never persisted, so a missing environment variable must be a clear
// failure rather than an attempt to open the token with an empty PIN — which
// some tokens count as a failed login attempt.
func TestResolvePKCS11MissingPINIsReported(t *testing.T) {
	h := newSoftHSM(t)
	h.generateEC(t, "ca")

	ref := h.ref(t, "ca")
	if err := os.Unsetenv("SIROS_WRPAC_TEST_PIN"); err != nil {
		t.Fatal(err)
	}
	_, err := ref.Resolve()
	if err == nil {
		t.Fatal("expected a missing PIN to fail")
	}
	if got := err.Error(); !contains(got, "SIROS_WRPAC_TEST_PIN") {
		t.Errorf("error should name the environment variable to set, got: %s", got)
	}
}

func TestResolvePKCS11WrongPINFails(t *testing.T) {
	h := newSoftHSM(t)
	h.generateEC(t, "ca")

	ref := h.ref(t, "ca")
	t.Setenv("SIROS_WRPAC_TEST_PIN", "9999")
	if _, err := ref.Resolve(); err == nil {
		t.Fatal("expected a wrong PIN to fail")
	}
}

func TestResolvePKCS11MissingModuleFails(t *testing.T) {
	ref := Ref{PKCS11: &PKCS11{
		Module:   "/nonexistent/libsofthsm2.so",
		KeyLabel: "ca",
		PINEnv:   "SIROS_WRPAC_TEST_PIN",
	}}
	t.Setenv("SIROS_WRPAC_TEST_PIN", "1234")
	if _, err := ref.Resolve(); err == nil {
		t.Fatal("expected a missing module to fail")
	}
}

func TestPKCS11RefRequiresModuleAndLabel(t *testing.T) {
	t.Setenv("SIROS_WRPAC_TEST_PIN", "1234")

	noModule := Ref{PKCS11: &PKCS11{KeyLabel: "ca", PINEnv: "SIROS_WRPAC_TEST_PIN"}}
	if _, err := noModule.Resolve(); err == nil {
		t.Error("expected a missing module path to fail")
	}

	noLabel := Ref{PKCS11: &PKCS11{Module: findModule(), PINEnv: "SIROS_WRPAC_TEST_PIN"}}
	if _, err := noLabel.Resolve(); err == nil {
		t.Error("expected a missing key label to fail")
	}
}

// Describe feeds logs and terminal output, so it must never leak the PIN.
func TestDescribeNeverLeaksThePIN(t *testing.T) {
	h := newSoftHSM(t)
	got := h.ref(t, "ca").Describe()
	if contains(got, h.pin) {
		t.Errorf("Describe leaked the PIN: %s", got)
	}
	for _, want := range []string{"ca", h.label, h.module} {
		if !contains(got, want) {
			t.Errorf("Describe should mention %q, got: %s", want, got)
		}
	}
}

func contains(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) &&
		(func() bool {
			for i := 0; i+len(needle) <= len(haystack); i++ {
				if haystack[i:i+len(needle)] == needle {
					return true
				}
			}
			return false
		})()
}
