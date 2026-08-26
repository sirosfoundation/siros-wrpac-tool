package jws

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"strings"
	"testing"
	"time"
)

func testKeyAndCert(t *testing.T) (crypto.Signer, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test"},
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
	return key, cert
}

func decodeSegment(t *testing.T, seg string) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// A JWS ES256 signature is the raw r||s pair. crypto/ecdsa emits ASN.1 DER, and
// signing with those bytes produces a token every verifier rejects.
func TestSignProducesRawRSSignature(t *testing.T) {
	key, cert := testKeyAndCert(t)
	tok, err := Sign("test+jwt", map[string]string{"a": "b"}, key, []*x509.Certificate{cert})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("want 3 segments, got %d", len(parts))
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != 64 {
		t.Fatalf("signature is %d bytes, want 64", len(sig))
	}
	if sig[0] == 0x30 {
		t.Error("signature looks like ASN.1 DER rather than raw r||s")
	}
}

// The signature must verify against the signing key over the exact signing
// input, which is what any consumer will reconstruct.
func TestSignatureVerifies(t *testing.T) {
	key, cert := testKeyAndCert(t)
	tok, err := Sign("test+jwt", map[string]string{"a": "b"}, key, []*x509.Certificate{cert})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok, ".")
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	pub := key.Public().(*ecdsa.PublicKey)
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		t.Error("signature does not verify over the signing input")
	}
}

func TestSignSetsTypAndX5C(t *testing.T) {
	key, cert := testKeyAndCert(t)
	tok, err := Sign("rc-wrp+jwt", map[string]string{}, key, []*x509.Certificate{cert})
	if err != nil {
		t.Fatal(err)
	}
	h := decodeSegment(t, strings.Split(tok, ".")[0])
	if h["typ"] != "rc-wrp+jwt" {
		t.Errorf("typ = %v", h["typ"])
	}
	if h["alg"] != "ES256" {
		t.Errorf("alg = %v", h["alg"])
	}
	if x5c, ok := h["x5c"].([]any); !ok || len(x5c) != 1 {
		t.Errorf("x5c = %v, want one entry", h["x5c"])
	}
}

func TestSignWithoutChainOmitsX5C(t *testing.T) {
	key, _ := testKeyAndCert(t)
	tok, err := Sign("test+jwt", map[string]string{}, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, present := decodeSegment(t, strings.Split(tok, ".")[0])["x5c"]; present {
		t.Error("x5c should be absent when no chain is supplied")
	}
}

func TestSignJAdESCarriesTheRequiredHeaders(t *testing.T) {
	key, cert := testKeyAndCert(t)
	tok, err := SignJAdES([]byte(`{"x":1}`), key, []*x509.Certificate{cert})
	if err != nil {
		t.Fatalf("SignJAdES: %v", err)
	}
	h := decodeSegment(t, strings.Split(tok, ".")[0])

	// ETSI TS 119 182-1 JAdES-B-B: signing time and the certificate thumbprint.
	if _, ok := h["iat"]; !ok {
		t.Error("iat is missing")
	}
	thumb := sha256.Sum256(cert.Raw)
	want := base64.RawURLEncoding.EncodeToString(thumb[:])
	if h["x5t#S256"] != want {
		t.Errorf("x5t#S256 = %v, want the SHA-256 thumbprint of the signing certificate", h["x5t#S256"])
	}
}

// The payload must be signed byte-for-byte as given, not re-marshalled — a LoTE
// is signed over the exact bytes that get published.
func TestSignJAdESPreservesPayloadBytes(t *testing.T) {
	key, cert := testKeyAndCert(t)
	payload := []byte(`{"b":2,"a":1}`)
	tok, err := SignJAdES(payload, key, []*x509.Certificate{cert})
	if err != nil {
		t.Fatal(err)
	}
	got, err := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Errorf("payload = %s, want the exact input bytes %s", got, payload)
	}
}

func TestSignJAdESRequiresACertificate(t *testing.T) {
	key, _ := testKeyAndCert(t)
	if _, err := SignJAdES([]byte(`{}`), key, nil); err == nil {
		t.Error("expected JAdES signing without a certificate to fail")
	}
}

func TestSignRejectsNonECDSAKeys(t *testing.T) {
	_, cert := testKeyAndCert(t)
	inner, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Sign("test+jwt", map[string]string{}, badSigner{inner: inner}, []*x509.Certificate{cert}); err == nil {
		t.Error("expected a non-ECDSA key to be rejected")
	}
}

// badSigner produces a valid DER signature but reports a non-ECDSA public key,
// so the r||s conversion has nothing to size itself against.
type badSigner struct{ inner *ecdsa.PrivateKey }

func (b badSigner) Public() crypto.PublicKey { return struct{}{} }
func (b badSigner) Sign(rnd io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return b.inner.Sign(rnd, digest, opts)
}
