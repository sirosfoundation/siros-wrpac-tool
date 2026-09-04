package tsl

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/xml"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/moov-io/signedxml"
	"github.com/sirosfoundation/g119612/pkg/etsi119612"
)

func testCert(t *testing.T, cn string, withSKI bool) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour).Truncate(time.Second),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	if withSKI {
		tmpl.SubjectKeyId = []byte{1, 2, 3, 4, 5}
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
	ca, _ := testCert(t, "Test Access CA", true)
	reg, _ := testCert(t, "Test Registrar", true)
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
		DistributionPoint: "https://r.test/tsl.xml",
		InformationURI:    "https://r.test",
		ElectronicAddress: "https://r.test/support",
		NextUpdate:        24 * time.Hour,
		IssuedAt:          time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}
}

func TestBuildListsEveryEntity(t *testing.T) {
	list, err := Build(testEntities(t), testOptions())
	if err != nil {
		t.Fatal(err)
	}
	tsps := list.TslTrustServiceProviderList.TslTrustServiceProvider
	if len(tsps) != 2 {
		t.Fatalf("got %d trust service providers, want 2", len(tsps))
	}

	svc := tsps[0].TslTSPServices.TslTSPService[0].TslServiceInformation
	if svc.TslServiceTypeIdentifier != ServiceTypeAccessCA {
		t.Errorf("service type = %q, want the Access CA type", svc.TslServiceTypeIdentifier)
	}
	// The inverse of the LoTE rule, and the one most likely to be copied across
	// by mistake: a TSL service without a status is invalid.
	if svc.TslServiceStatus != ServiceStatusGranted {
		t.Errorf("service status = %q, want %q", svc.TslServiceStatus, ServiceStatusGranted)
	}
	if svc.TslServiceDigitalIdentity.DigitalId[0].X509Certificate == "" {
		t.Error("digital identity carries no certificate")
	}
}

func TestBuildDoesNotClaimEUSupervision(t *testing.T) {
	// EUgeneric/EUlistofthelists assert publication under the eIDAS supervisory
	// framework. A deployment run by this tool is not supervised, and a list
	// that says otherwise is a false claim rather than a cosmetic default.
	list, err := Build(testEntities(t), testOptions())
	if err != nil {
		t.Fatal(err)
	}
	got := list.TslSchemeInformation.TslTSLType
	if got != TSLTypeGeneric {
		t.Errorf("TSLType = %q, want %q", got, TSLTypeGeneric)
	}
	if strings.Contains(got, "EUgeneric") || strings.Contains(got, "EUlistofthelists") {
		t.Errorf("TSLType %q claims an EU-supervised list", got)
	}
}

func TestBuildRejectsNothingToPublish(t *testing.T) {
	if _, err := Build(nil, testOptions()); err == nil {
		t.Fatal("expected an error for an empty entity list")
	}
}

func TestBuildRejectsAnEntityWithoutACertificate(t *testing.T) {
	_, err := Build([]Entity{{Name: "No cert", ServiceType: ServiceTypeAccessCA}}, testOptions())
	if err == nil {
		t.Fatal("expected an error for an entity with no certificate")
	}
	if !strings.Contains(err.Error(), "No cert") {
		t.Errorf("error should name the entity, got %v", err)
	}
}

func TestMarshalRoundTrips(t *testing.T) {
	list, err := Build(testEntities(t), testOptions())
	if err != nil {
		t.Fatal(err)
	}
	data, err := Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), xml.Header) {
		t.Error("output has no XML declaration")
	}
	// Namespace bindings are not in the generated type; without them a consumer
	// cannot resolve the element names it is looking for.
	if !strings.Contains(string(data), `xmlns:tsl="`+nsTSL+`"`) {
		t.Error("output does not bind the tsl namespace")
	}

	var back struct {
		SchemeInformation struct {
			TSLSequenceNumber int    `xml:"TSLSequenceNumber"`
			SchemeTerritory   string `xml:"SchemeTerritory"`
		} `xml:"SchemeInformation"`
		Providers struct {
			Provider []struct {
				Services struct {
					Service []struct {
						Info struct {
							TypeIdentifier string `xml:"ServiceTypeIdentifier"`
							Status         string `xml:"ServiceStatus"`
						} `xml:"ServiceInformation"`
					} `xml:"TSPService"`
				} `xml:"TSPServices"`
			} `xml:"TrustServiceProvider"`
		} `xml:"TrustServiceProviderList"`
	}
	if err := xml.Unmarshal(data, &back); err != nil {
		t.Fatalf("generated XML does not parse: %v", err)
	}
	if back.SchemeInformation.TSLSequenceNumber != 3 {
		t.Errorf("sequence number = %d, want 3", back.SchemeInformation.TSLSequenceNumber)
	}
	if back.SchemeInformation.SchemeTerritory != "SE" {
		t.Errorf("territory = %q, want SE", back.SchemeInformation.SchemeTerritory)
	}
	if len(back.Providers.Provider) != 2 {
		t.Fatalf("parsed %d providers, want 2", len(back.Providers.Provider))
	}
	if s := back.Providers.Provider[0].Services.Service[0].Info.Status; s != ServiceStatusGranted {
		t.Errorf("parsed status = %q, want %q", s, ServiceStatusGranted)
	}
}

func TestSignedListValidates(t *testing.T) {
	// The point of the whole signing path: a consumer must be able to verify
	// the signature. Producing bytes that merely look like XMLDSig would pass a
	// shape check and fail here.
	entities := testEntities(t)
	list, err := Build(entities, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	cert, key := testCert(t, "Test Registrar Signing", true)
	signer, err := NewSigner(key, []*x509.Certificate{cert})
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	written, err := Publish(list, dir, signer)
	if err != nil {
		t.Fatal(err)
	}
	if len(written) != 1 {
		t.Fatalf("wrote %d files, want 1 - the signature is enveloped, not detached", len(written))
	}
	data, err := os.ReadFile(written[0]) //nolint:gosec // test-controlled path
	if err != nil {
		t.Fatal(err)
	}

	validator, err := signedxml.NewValidator(string(data))
	if err != nil {
		t.Fatalf("signed document does not parse: %v", err)
	}
	validator.Certificates = append(validator.Certificates, *cert)
	if _, err := validator.ValidateReferences(); err != nil {
		t.Fatalf("signature does not validate: %v", err)
	}
}

func TestSignatureCoversTheDocument(t *testing.T) {
	// An enveloped signature that does not actually cover the content would
	// validate over a tampered list, which is the failure that matters.
	list, err := Build(testEntities(t), testOptions())
	if err != nil {
		t.Fatal(err)
	}
	cert, key := testCert(t, "Test Registrar Signing", true)
	signer, err := NewSigner(key, []*x509.Certificate{cert})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign(mustMarshal(t, list))
	if err != nil {
		t.Fatal(err)
	}

	tampered := strings.Replace(string(signed), "<SchemeTerritory>SE</SchemeTerritory>",
		"<SchemeTerritory>NO</SchemeTerritory>", 1)
	if tampered == string(signed) {
		t.Fatal("test did not manage to tamper with the document")
	}

	validator, err := signedxml.NewValidator(tampered)
	if err != nil {
		t.Fatalf("tampered document does not parse: %v", err)
	}
	validator.Certificates = append(validator.Certificates, *cert)
	if _, err := validator.ValidateReferences(); err == nil {
		t.Fatal("a tampered list still validated - the signature does not cover the content")
	}
}

func TestPublishWithoutASignerWritesAnUnsignedList(t *testing.T) {
	list, err := Build(testEntities(t), testOptions())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	written, err := Publish(list, dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(written[0]) //nolint:gosec // test-controlled path
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "ds:Signature") {
		t.Error("unsigned publication contains a signature element")
	}
}

func TestFilenameFollowsTheDistributionPoint(t *testing.T) {
	cases := []struct {
		name string
		opts func(Options) Options
		want string
	}{
		{"from the distribution point", func(o Options) Options { return o }, "tsl.xml"},
		{
			"a different basename",
			func(o Options) Options { o.DistributionPoint = "https://r.test/lists/anchors.xml"; return o },
			"anchors.xml",
		},
		{
			"territory when there is no distribution point",
			func(o Options) Options { o.DistributionPoint = ""; return o },
			"tsl-SE.xml",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			list, err := Build(testEntities(t), tc.opts(testOptions()))
			if err != nil {
				t.Fatal(err)
			}
			if got := Filename(list); got != tc.want {
				t.Errorf("Filename() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSubjectKeyIdentifierUsesTheCertificatesOwn(t *testing.T) {
	cert, _ := testCert(t, "With SKI", true)
	want := base64.StdEncoding.EncodeToString([]byte{1, 2, 3, 4, 5})
	if got := subjectKeyIdentifier(cert); got != want {
		t.Errorf("SKI = %q, want the certificate's own %q", got, want)
	}
}

func TestSubjectKeyIdentifierFallsBackRatherThanEmitNothing(t *testing.T) {
	// An empty X509SKI is schema-invalid, so a certificate without the
	// extension has to be handled rather than passed through.
	cert, _ := testCert(t, "No SKI", false)
	if len(cert.SubjectKeyId) != 0 {
		t.Skip("test certificate unexpectedly carries an SKI")
	}
	got := subjectKeyIdentifier(cert)
	if got == "" {
		t.Fatal("no SKI derived for a certificate without the extension")
	}
	raw, err := base64.StdEncoding.DecodeString(got)
	if err != nil {
		t.Fatalf("derived SKI is not base64: %v", err)
	}
	if len(raw) != 20 {
		t.Errorf("derived SKI is %d bytes, want the 20 of a SHA-1 digest", len(raw))
	}
}

func TestAlgorithmsMatchTheSigningKey(t *testing.T) {
	// The signature must verify against the certificate in KeyInfo, so the
	// algorithm is derived from the key rather than chosen by a caller.
	p256, _ := testCert(t, "P-256", true)
	sig, digest, _, err := algorithmsFor(p256.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sig, "ecdsa-sha256") {
		t.Errorf("signature algorithm = %q, want ECDSA/SHA-256 for a P-256 key", sig)
	}
	if !strings.Contains(digest, "sha256") {
		t.Errorf("digest algorithm = %q, want SHA-256", digest)
	}

	rsaCert := rsaTestCert(t)
	sig, _, _, err = algorithmsFor(rsaCert.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sig, "rsa-sha256") {
		t.Errorf("signature algorithm = %q, want RSA/SHA-256 for an RSA key", sig)
	}
}

func TestNewSignerRejectsIncompleteInput(t *testing.T) {
	cert, key := testCert(t, "Signer", true)
	if _, err := NewSigner(nil, []*x509.Certificate{cert}); err == nil {
		t.Error("expected an error with no key")
	}
	if _, err := NewSigner(key, nil); err == nil {
		t.Error("expected an error with no certificate chain")
	}
}

func TestMarshalRejectsNil(t *testing.T) {
	if _, err := Marshal(nil); err == nil {
		t.Fatal("expected an error marshalling nil")
	}
}

func TestFilenameFallsBackWithoutSchemeInformation(t *testing.T) {
	if got := Filename(&etsi119612.TrustStatusListType{}); got != "tsl.xml" {
		t.Errorf("Filename() = %q, want tsl.xml", got)
	}
}

func TestPublishCreatesTheOutputDirectory(t *testing.T) {
	list, err := Build(testEntities(t), testOptions())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "nested", "public")
	if _, err := Publish(list, dir, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "tsl.xml")); err != nil {
		t.Fatalf("expected the list in a created directory: %v", err)
	}
}

func mustMarshal(t *testing.T, list *etsi119612.TrustStatusListType) []byte {
	t.Helper()
	data, err := Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func rsaTestCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "RSA"},
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
	return cert
}

// TestG119612ParsesWhatWePublish reads the output back with the same library a
// consumer uses, rather than with a local struct shaped to match the writer.
// A document can round-trip through its own author's expectations and still be
// unreadable by anything else — the missing default namespace that made every
// child element namespace-less did exactly that, and passed a hand-rolled
// round-trip test while doing it.
func TestG119612ParsesWhatWePublish(t *testing.T) {
	list, err := Build(testEntities(t), testOptions())
	if err != nil {
		t.Fatal(err)
	}
	data, err := Marshal(list)
	if err != nil {
		t.Fatal(err)
	}

	var parsed etsi119612.TrustStatusListType
	if err := xml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("g119612's own type could not parse the output: %v", err)
	}
	if parsed.TslSchemeInformation == nil {
		t.Fatal("parsed list has no scheme information")
	}
	if parsed.TslSchemeInformation.TSLSequenceNumber != 3 {
		t.Errorf("parsed sequence = %d, want 3", parsed.TslSchemeInformation.TSLSequenceNumber)
	}
	if parsed.TslTrustServiceProviderList == nil {
		t.Fatal("parsed list has no trust service providers")
	}
	tsps := parsed.TslTrustServiceProviderList.TslTrustServiceProvider
	if len(tsps) != 2 {
		t.Fatalf("parsed %d providers, want 2", len(tsps))
	}

	svc := tsps[0].TslTSPServices.TslTSPService[0].TslServiceInformation
	if svc.TslServiceTypeIdentifier != ServiceTypeAccessCA {
		t.Errorf("parsed service type = %q, want the Access CA type", svc.TslServiceTypeIdentifier)
	}
	// The certificate is the entire point of the list: a consumer that cannot
	// recover it has nothing to anchor trust on.
	raw, err := base64.StdEncoding.DecodeString(svc.TslServiceDigitalIdentity.DigitalId[0].X509Certificate)
	if err != nil {
		t.Fatalf("parsed certificate is not base64: %v", err)
	}
	if _, err := x509.ParseCertificate(raw); err != nil {
		t.Fatalf("parsed certificate does not decode: %v", err)
	}
}

// TestChildElementsAreInTheTSLNamespace pins the bug above directly.
func TestChildElementsAreInTheTSLNamespace(t *testing.T) {
	list, err := Build(testEntities(t), testOptions())
	if err != nil {
		t.Fatal(err)
	}
	data, err := Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `xmlns="`+nsTSL+`"`) {
		t.Error("no default namespace: every unprefixed child element would be in no namespace")
	}
}
