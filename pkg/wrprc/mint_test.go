package wrprc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"
)

func testSigner(t *testing.T) *Signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test Registrar"},
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
	return &Signer{Chain: []*x509.Certificate{cert}, Key: key}
}

func providerPayload() Payload {
	return Payload{
		Name:         "Example Provider",
		Sub:          "LEIXG-529900T8BM49AURSDO55",
		Entitlements: []string{EntitlementPIDProvider},
		ProvidesAttestations: []Credential{
			{Format: "dc+sd-jwt", Meta: map[string]any{"vct_values": []string{"urn:eudi:pid:1"}}},
		},
	}
}

func decodePayload(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected a compact JWS with 3 parts, got %d", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestMintUsesV121FieldNames(t *testing.T) {
	token, err := testSigner(t).Mint(providerPayload())
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	claims := decodePayload(t, token)

	// V1.2.1 spells this provides_attestations; V1.1.1 used provided_attestations.
	if _, ok := claims["provides_attestations"]; !ok {
		t.Error("payload is missing provides_attestations")
	}
	if _, ok := claims["provided_attestations"]; ok {
		t.Error("payload uses the V1.1.1 spelling provided_attestations")
	}
	// sub is a flat string in V1.2.1, not an object.
	if _, ok := claims["sub"].(string); !ok {
		t.Errorf("sub should be a flat string, got %T", claims["sub"])
	}
}

func TestMintSetsMediaTypeAndX5C(t *testing.T) {
	token, err := testSigner(t).Mint(providerPayload())
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[0])
	if err != nil {
		t.Fatal(err)
	}
	var hdr map[string]any
	if err := json.Unmarshal(raw, &hdr); err != nil {
		t.Fatal(err)
	}
	if hdr["typ"] != MediaType {
		t.Errorf("typ = %v, want %s", hdr["typ"], MediaType)
	}
	if _, ok := hdr["x5c"].([]any); !ok {
		t.Error("header is missing an x5c chain")
	}
}

func TestMintRejectsProvidesAttestationsWithoutProviderEntitlement(t *testing.T) {
	p := providerPayload()
	p.Entitlements = []string{EntitlementServiceProvider}
	if _, err := testSigner(t).Mint(p); err == nil {
		t.Fatal("expected provides_attestations on a non-provider to be rejected")
	}
}

func TestMintEnforcesTwelveMonthCeiling(t *testing.T) {
	p := providerPayload()
	p.IssuedAt = time.Now().UTC().Unix()
	p.ExpiresAt = time.Unix(p.IssuedAt, 0).AddDate(0, 13, 0).Unix()
	if _, err := testSigner(t).Mint(p); err == nil {
		t.Fatal("expected exp beyond iat+12 months to be rejected (GEN-5.2.4-08)")
	}
}

func TestMintRequiresEntitlement(t *testing.T) {
	p := providerPayload()
	p.Entitlements = nil
	if _, err := testSigner(t).Mint(p); err == nil {
		t.Fatal("expected a payload with no entitlements to be rejected (GEN-5.2.4-03)")
	}
}

func TestSignatureIsRawRS(t *testing.T) {
	token, err := testSigner(t).Mint(providerPayload())
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[2])
	if err != nil {
		t.Fatal(err)
	}
	// ES256 signatures are exactly 64 bytes; an ASN.1 DER signature would not be.
	if len(sig) != 64 {
		t.Errorf("signature length = %d, want 64 (raw r||s)", len(sig))
	}
}
