// Package tsl publishes the deployment's trust anchors as an ETSI TS 119 612
// Trust Status List.
//
// This is the same statement pkg/lote makes, in the other format the ecosystem
// reads. LoTE (TS 119 602) is the newer JSON list the EUDI wallet ecosystem is
// moving to; TSL (TS 119 612) is the XML list that eIDAS trusted lists have
// always used and that every existing trusted-list consumer already speaks.
// Publishing both means a deployment can be trusted by either without operating
// two tools.
//
// Two things differ from LoTE and are easy to get backwards:
//
//   - ServiceStatus is REQUIRED here and FORBIDDEN there. In a LoTE, presence in
//     the list is itself the trust statement; in a TSL every service carries an
//     explicit status URI.
//   - The signature is an enveloped XMLDSig inside the document, not a detached
//     JWS beside it. There is no unsigned-plus-signature pair to publish.
//
// As in pkg/lote the document is built from g119612's own generated types, so
// there is one implementation of the schema in the ecosystem rather than two.
package tsl

import (
	"crypto"
	"crypto/sha1" //nolint:gosec // RFC 5280 4.2.1.2 defines the SKI as a SHA-1 hash; not a security decision.
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirosfoundation/g119612/pkg/etsi119612"

	"github.com/sirosfoundation/siros-wrpac-tool/pkg/lote"
)

// Entity is one trust service to list.
//
// Deliberately an alias rather than a parallel struct: a deployment publishes
// the same anchors to both lists, and two shapes that must agree are two shapes
// that will eventually disagree.
type Entity = lote.Entity

// Service type identifiers, mirroring pkg/lote's.
//
// TS 119 612's own registry has no entries for the CIR (EU) 2025/848 services,
// so these reuse the ETSI 19475 namespace the entitlement URIs already use — the
// same choice, and the same caveat, as in pkg/lote. Revisit together when the
// official identifiers are published.
const (
	ServiceTypeAccessCA                 = lote.ServiceTypeAccessCA
	ServiceTypeRegistrationCertProvider = lote.ServiceTypeRegistrationCertProvider
)

// ServiceStatusGranted is the TS 119 612 status for a service in force.
//
// Unlike a LoTE, a TSL requires a status on every service, so this is always
// written. It says the deployment considers the service current; it makes no
// claim of supervision under a national scheme.
const ServiceStatusGranted = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"

// TSLTypeGeneric is the default list type.
//
// Deliberately not one of the EUgeneric/EUlistofthelists/CClist values: those
// assert a list published under the eIDAS supervisory framework, which a
// deployment run by this tool is not. Override with Options.TSLType when
// publishing into a scheme that defines its own.
const TSLTypeGeneric = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/generic"

// StatusDeterminationAppropriate matches what pkg/lote writes.
const StatusDeterminationAppropriate = "http://uri.etsi.org/TrstSvc/TrustedList/StatusDetn/EUappropriate"

// XML namespaces a TS 119 612 consumer expects to find bound.
const (
	nsTSL  = "http://uri.etsi.org/02231/v2#"
	nsDS   = "http://www.w3.org/2000/09/xmldsig#"
	tslTag = "http://uri.etsi.org/19612/TSLTag"
)

// Options configure Build. They mirror lote.Options field for field where the
// two formats mean the same thing.
type Options struct {
	// SequenceNumber must increase on every republication.
	SequenceNumber int
	// Territory is the ISO 3166-1 alpha-2 scheme territory.
	Territory string
	// OperatorName is the scheme operator.
	OperatorName string
	// SchemeName describes the list.
	SchemeName string
	// DistributionPoint is the URL this list is published at. It also determines
	// the output filename.
	DistributionPoint string
	// InformationURI documents the scheme.
	InformationURI string
	// ElectronicAddress is the scheme operator's contact URI. TS 119 612
	// requires an address on the scheme operator.
	ElectronicAddress string
	// NextUpdate is how long the list claims to be current for.
	NextUpdate time.Duration
	// IssuedAt fixes the issue time; zero means now.
	IssuedAt time.Time
	// TSLType overrides TSLTypeGeneric.
	TSLType string
	// HistoricalInformationPeriod is in days. Zero means 65535.
	HistoricalInformationPeriod int
}

// Build assembles a TSL listing the supplied entities.
func Build(entities []Entity, opts Options) (*etsi119612.TrustStatusListType, error) {
	if len(entities) == 0 {
		return nil, fmt.Errorf("tsl: no entities to publish")
	}
	if opts.NextUpdate == 0 {
		opts.NextUpdate = 90 * 24 * time.Hour
	}
	if opts.TSLType == "" {
		opts.TSLType = TSLTypeGeneric
	}
	if opts.HistoricalInformationPeriod == 0 {
		opts.HistoricalInformationPeriod = 65535
	}
	issued := opts.IssuedAt
	if issued.IsZero() {
		issued = time.Now()
	}
	issued = issued.UTC()

	info := &etsi119612.TSLSchemeInformationType{
		TSLVersionIdentifier:        5,
		TSLSequenceNumber:           opts.SequenceNumber,
		TslTSLType:                  opts.TSLType,
		TslSchemeOperatorName:       names(opts.OperatorName),
		TslSchemeName:               names(opts.SchemeName),
		StatusDeterminationApproach: StatusDeterminationAppropriate,
		TslSchemeTerritory:          opts.Territory,
		HistoricalInformationPeriod: opts.HistoricalInformationPeriod,
		ListIssueDateTime:           issued.Format(time.RFC3339),
		TslNextUpdate: &etsi119612.NextUpdateType{
			DateTime: issued.Add(opts.NextUpdate).Format(time.RFC3339),
		},
	}
	if opts.ElectronicAddress != "" {
		info.SchemeOperatorAddress = &etsi119612.AddressType{
			TslElectronicAddress: &etsi119612.ElectronicAddressType{
				URI: []*etsi119612.NonEmptyMultiLangURIType{uri(opts.ElectronicAddress)},
			},
		}
	}
	if opts.InformationURI != "" {
		info.TslSchemeInformationURI = &etsi119612.NonEmptyMultiLangURIListType{
			URI: []*etsi119612.NonEmptyMultiLangURIType{uri(opts.InformationURI)},
		}
	}
	if opts.DistributionPoint != "" {
		info.TslDistributionPoints = &etsi119612.NonEmptyURIListType{URI: []string{opts.DistributionPoint}}
	}

	providers := &etsi119612.TrustServiceProviderListType{}
	for _, e := range entities {
		if e.Certificate == nil {
			return nil, fmt.Errorf("tsl: entity %q has no certificate", e.Name)
		}
		tsp := &etsi119612.TSPType{
			TslTSPInformation: &etsi119612.TSPInformationType{
				TSPName: names(e.Name),
				TSPAddress: &etsi119612.AddressType{
					TslElectronicAddress: &etsi119612.ElectronicAddressType{
						URI: []*etsi119612.NonEmptyMultiLangURIType{uri(e.ElectronicAddress)},
					},
				},
				TSPInformationURI: &etsi119612.NonEmptyMultiLangURIListType{
					URI: []*etsi119612.NonEmptyMultiLangURIType{uri(e.InformationURI)},
				},
			},
			TslTSPServices: &etsi119612.TSPServicesListType{
				TslTSPService: []*etsi119612.TSPServiceType{{
					TslServiceInformation: &etsi119612.TSPServiceInformationType{
						TslServiceTypeIdentifier: e.ServiceType,
						ServiceName:              names(e.Name),
						// Required here, forbidden in a LoTE. See the package comment.
						TslServiceStatus:   ServiceStatusGranted,
						StatusStartingTime: e.Certificate.NotBefore.UTC().Format(time.RFC3339),
						TslServiceDigitalIdentity: &etsi119612.DigitalIdentityListType{
							DigitalId: []*etsi119612.DigitalIdentityType{{
								X509Certificate: base64.StdEncoding.EncodeToString(e.Certificate.Raw),
								X509SubjectName: e.Certificate.Subject.String(),
								X509SKI:         subjectKeyIdentifier(e.Certificate),
							}},
						},
					},
				}},
			},
		}
		if e.TradeName != "" {
			tsp.TslTSPInformation.TSPTradeName = names(e.TradeName)
		}
		providers.TslTrustServiceProvider = append(providers.TslTrustServiceProvider, tsp)
	}

	return &etsi119612.TrustStatusListType{
		TSLTagAttr:                  tslTag,
		IdAttr:                      "siros-tsl",
		TslSchemeInformation:        info,
		TslTrustServiceProviderList: providers,
	}, nil
}

// subjectKeyIdentifier returns the certificate's SKI, base64-encoded.
//
// Falls back to RFC 5280 4.2.1.2 method 1 — the SHA-1 of the subject public key
// BIT STRING — when the certificate carries no SKI extension, because that is
// the value its issuer would have put there. Emitting an empty X509SKI would
// produce a schema-invalid document, which is worse than deriving the value the
// standard already defines.
func subjectKeyIdentifier(cert *x509.Certificate) string {
	if len(cert.SubjectKeyId) > 0 {
		return base64.StdEncoding.EncodeToString(cert.SubjectKeyId)
	}
	var spki struct {
		Algorithm        pkix1AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &spki); err != nil {
		return ""
	}
	sum := sha1.Sum(spki.SubjectPublicKey.Bytes) //nolint:gosec // see the doc comment
	return base64.StdEncoding.EncodeToString(sum[:])
}

// pkix1AlgorithmIdentifier is the AlgorithmIdentifier half of a
// SubjectPublicKeyInfo. Declared locally because x509's own copy is unexported
// and only the BIT STRING that follows it is needed.
type pkix1AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// tslEnvelope binds the namespaces on the root element. The generated type
// carries the element names but not the bindings a consumer needs to resolve
// them.
type tslEnvelope struct {
	XMLName xml.Name `xml:"tsl:TrustServiceStatusList"`
	// The default namespace matters as much as the prefix binding: every child
	// element the generated types emit is unprefixed, so without an xmlns here
	// they would land in no namespace at all and a TS 119 612 consumer looking
	// for them in the 02231 namespace would find an empty list.
	NsDefault string `xml:"xmlns,attr"`
	NsTSL     string `xml:"xmlns:tsl,attr"`
	NsDS      string `xml:"xmlns:ds,attr"`
	*etsi119612.TrustStatusListType
}

// Marshal renders the list as XML, with the declaration and namespace bindings.
func Marshal(list *etsi119612.TrustStatusListType) ([]byte, error) {
	if list == nil {
		return nil, fmt.Errorf("tsl: nothing to marshal")
	}
	body, err := xml.MarshalIndent(&tslEnvelope{
		NsDefault:           nsTSL,
		NsTSL:               nsTSL,
		NsDS:                nsDS,
		TrustStatusListType: list,
	}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("tsl: marshal: %w", err)
	}
	// Grown by append rather than pre-sized: the capacity hint was three
	// lengths added together, which CodeQL flags as an allocation size that
	// could overflow. The hint bought nothing measurable on a document this
	// size, and append reaches the same result without the arithmetic.
	var out []byte
	out = append(out, xml.Header...)
	out = append(out, body...)
	return append(out, '\n'), nil
}

// Filename mirrors lote.Filename: the basename of the distribution point path
// with an .xml extension, falling back to the territory.
func Filename(list *etsi119612.TrustStatusListType) string {
	info := list.TslSchemeInformation
	if info == nil {
		return "tsl.xml"
	}
	if info.TslDistributionPoints != nil && len(info.TslDistributionPoints.URI) > 0 {
		if u, err := url.Parse(info.TslDistributionPoints.URI[0]); err == nil && u.Path != "" {
			base := filepath.Base(u.Path)
			if base != "" && base != "." && base != "/" {
				if ext := filepath.Ext(base); ext != "" {
					base = strings.TrimSuffix(base, ext)
				}
				return base + ".xml"
			}
		}
	}
	if info.TslSchemeTerritory != "" {
		return fmt.Sprintf("tsl-%s.xml", info.TslSchemeTerritory)
	}
	return "tsl.xml"
}

// Publish writes the TSL into dir, signing it in place when a signer is given.
//
// Unlike pkg/lote this writes one file, not two: an XMLDSig signature is
// enveloped in the document, so there is no detached signature to publish and
// no reason to leave an unsigned copy beside a signed one.
func Publish(list *etsi119612.TrustStatusListType, dir string, signer *Signer) ([]string, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("tsl: create %s: %w", dir, err)
	}
	data, err := Marshal(list)
	if err != nil {
		return nil, err
	}
	if signer != nil {
		data, err = signer.Sign(data)
		if err != nil {
			return nil, err
		}
	}

	path := filepath.Join(dir, Filename(list))
	if err := os.WriteFile(path, data, 0o640); err != nil {
		return nil, fmt.Errorf("tsl: write %s: %w", path, err)
	}
	return []string{path}, nil
}

// Signer produces the enveloped XMLDSig signature.
//
// Holds a crypto.Signer rather than a concrete key so a PKCS#11 token works here
// exactly as it does for LoTE: the signedxml fork this module replaces moov-io's
// with accepts any crypto.Signer.
type Signer struct {
	key   crypto.Signer
	chain []*x509.Certificate
}

// NewSigner builds a signer over any crypto.Signer.
func NewSigner(key crypto.Signer, chain []*x509.Certificate) (*Signer, error) {
	if key == nil {
		return nil, fmt.Errorf("tsl: no signing key")
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("tsl: no signing certificate chain")
	}
	return &Signer{key: key, chain: chain}, nil
}

// Sign returns doc with an enveloped XMLDSig signature over the whole document.
func (s *Signer) Sign(doc []byte) ([]byte, error) {
	return signEnveloped(doc, s.key, s.chain)
}

func names(v string) *etsi119612.InternationalNamesType {
	s := etsi119612.NonEmptyNormalizedString(v)
	lang := etsi119612.Lang("en")
	return &etsi119612.InternationalNamesType{
		Name: []*etsi119612.MultiLangNormStringType{{
			XmlLangAttr:              &lang,
			NonEmptyNormalizedString: &s,
		}},
	}
}

func uri(v string) *etsi119612.NonEmptyMultiLangURIType {
	lang := etsi119612.Lang("en")
	return &etsi119612.NonEmptyMultiLangURIType{XmlLangAttr: &lang, Value: v}
}
