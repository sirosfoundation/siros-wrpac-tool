// Package lote publishes the deployment's trust anchors as an ETSI TS 119 602
// List of Trusted Entities.
//
// A wallet needs the Access CA and the registration certificate provider as
// trust anchors before it can verify anything this tool issues. LoTE is how the
// EUDI ecosystem distributes them, and go-trust's pkg/registry/lote already
// consumes the format.
//
// The document is built with g119612's own types rather than a local encoder, so
// there is one implementation of the schema in the ecosystem instead of two, and
// the output drops straight into a tsl-tool pipeline.
package lote

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirosfoundation/g119612/pkg/etsi119602"

	sirosjws "github.com/sirosfoundation/siros-wrpac-tool/pkg/jws"
)

// Service type identifiers for the two roles a deployment operates.
//
// CIR (EU) 2025/848 names these services but TS 119 612's registry has no
// entries for them yet, so they are expressed under the ETSI 19475 namespace
// that the entitlement URIs already use. Revisit when the official identifiers
// are published — a consumer matching on these strings will need updating.
const (
	ServiceTypeAccessCA                 = "https://uri.etsi.org/19475/Svctype/WRPAccessCertificateProvider"
	ServiceTypeRegistrationCertProvider = "https://uri.etsi.org/19475/Svctype/WRPRegistrationCertificateProvider"
)

// Entity is one trust service to list.
type Entity struct {
	Name        string
	TradeName   string
	ServiceType string
	Certificate *x509.Certificate
	// InformationURI is where a reader can find out about the entity.
	InformationURI string
	// ElectronicAddress is a contact URI, required by the TEAddress schema.
	ElectronicAddress string
}

// Options configure Build.
type Options struct {
	// SequenceNumber must increase on every republication. A consumer that sees
	// a sequence number it already holds may skip the document entirely.
	SequenceNumber int
	// Territory is the ISO 3166-1 alpha-2 scheme territory.
	Territory string
	// OperatorName is the scheme operator.
	OperatorName string
	// SchemeName describes the list.
	SchemeName string
	// DistributionPoint is the URL this list is published at. It also determines
	// the output filename, matching g119612's publish-lote step.
	DistributionPoint string
	// InformationURI documents the scheme.
	InformationURI string
	// NextUpdate is how long the list claims to be current for.
	NextUpdate time.Duration
	// IssuedAt fixes the issue time; zero means now.
	IssuedAt time.Time
}

// Build assembles a LoTE listing the supplied entities.
func Build(entities []Entity, opts Options) (*etsi119602.ListOfTrustedEntities, error) {
	if len(entities) == 0 {
		return nil, fmt.Errorf("lote: no entities to publish")
	}
	if opts.NextUpdate == 0 {
		opts.NextUpdate = 90 * 24 * time.Hour
	}
	issued := opts.IssuedAt
	if issued.IsZero() {
		issued = time.Now()
	}
	issued = issued.UTC()

	list := &etsi119602.ListOfTrustedEntities{
		ListAndSchemeInformation: etsi119602.ListAndSchemeInformation{
			LoTEVersionIdentifier:       1,
			LoTESequenceNumber:          opts.SequenceNumber,
			SchemeOperatorName:          names(opts.OperatorName),
			SchemeName:                  names(opts.SchemeName),
			SchemeTerritory:             opts.Territory,
			ListIssueDateTime:           issued.Format(time.RFC3339),
			NextUpdate:                  issued.Add(opts.NextUpdate).Format(time.RFC3339),
			StatusDeterminationApproach: "http://uri.etsi.org/TrstSvc/TrustedList/StatusDetn/EUappropriate",
		},
	}
	if opts.DistributionPoint != "" {
		list.ListAndSchemeInformation.DistributionPoints = []string{opts.DistributionPoint}
	}
	if opts.InformationURI != "" {
		list.ListAndSchemeInformation.SchemeInformationURI = []etsi119602.NonEmptyMultiLangURI{
			{Lang: "en", URIValue: opts.InformationURI},
		}
	}

	for _, e := range entities {
		if e.Certificate == nil {
			return nil, fmt.Errorf("lote: entity %q has no certificate", e.Name)
		}
		te := etsi119602.TrustedEntity{
			TrustedEntityInformation: etsi119602.TrustedEntityInformation{
				TEName: names(e.Name),
				TEAddress: &etsi119602.TEAddress{
					TEElectronicAddress: []etsi119602.NonEmptyMultiLangURI{
						{Lang: "en", URIValue: e.ElectronicAddress},
					},
				},
				TEInformationURI: []etsi119602.NonEmptyMultiLangURI{
					{Lang: "en", URIValue: e.InformationURI},
				},
			},
			TrustedEntityServices: []etsi119602.TrustedEntityService{{
				ServiceInformation: etsi119602.ServiceInformation{
					ServiceName:           names(e.Name),
					ServiceTypeIdentifier: e.ServiceType,
					// ServiceStatus is deliberately absent. Outside the PuB-EAA
					// profile, LoTE treats presence in the list as the trust
					// statement; setting a status here is rejected by the schema.
					StatusStartingTime: e.Certificate.NotBefore.UTC().Format(time.RFC3339),
					ServiceDigitalIdentity: etsi119602.ServiceDigitalIdentity{
						X509Certificates: []etsi119602.PKIOb{{
							Encoding: "base64",
							Val:      base64.StdEncoding.EncodeToString(e.Certificate.Raw),
						}},
						X509SubjectNames: []string{e.Certificate.Subject.String()},
					},
				},
			}},
		}
		if e.TradeName != "" {
			te.TrustedEntityInformation.TETradeName = names(e.TradeName)
		}
		list.TrustedEntitiesList = append(list.TrustedEntitiesList, te)
	}

	// Validate before anyone can write it: a structurally invalid LoTE that
	// reaches a distribution point is worse than none, because consumers cache.
	if err := list.Validate(); err != nil {
		return nil, fmt.Errorf("lote: generated document is invalid: %w", err)
	}
	return list, nil
}

// Filename reproduces g119612's publish-lote naming: the basename of the
// distribution point path with a .json extension, falling back to the territory.
// Matching it means output from this tool and from a tsl-tool pipeline land on
// the same filenames.
func Filename(list *etsi119602.ListOfTrustedEntities) string {
	info := list.ListAndSchemeInformation
	if len(info.DistributionPoints) > 0 {
		if u, err := url.Parse(info.DistributionPoints[0]); err == nil && u.Path != "" {
			base := filepath.Base(u.Path)
			if base != "" && base != "." && base != "/" {
				if ext := filepath.Ext(base); ext != "" {
					base = strings.TrimSuffix(base, ext)
				}
				return base + ".json"
			}
		}
	}
	if info.SchemeTerritory != "" {
		return fmt.Sprintf("lote-%s.json", info.SchemeTerritory)
	}
	return "lote.json"
}

// Publish writes the LoTE into dir in the layout g119612's publish-lote step
// produces: the unsigned JSON, plus a detached compact JWS alongside it when a
// signer is supplied.
//
// The unsigned document is always written, even when signing, because that is
// what publish-lote does and a pipeline reading the directory expects both.
func Publish(list *etsi119602.ListOfTrustedEntities, dir string, signer Signer) ([]string, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("lote: create %s: %w", dir, err)
	}
	data, err := list.MarshalIndent()
	if err != nil {
		return nil, fmt.Errorf("lote: marshal: %w", err)
	}

	name := Filename(list)
	path := filepath.Join(dir, name)
	written := []string{path}

	if err := os.WriteFile(path, data, 0o640); err != nil {
		return nil, fmt.Errorf("lote: write %s: %w", path, err)
	}

	if signer != nil {
		compact, err := signer.Sign(data)
		if err != nil {
			return nil, fmt.Errorf("lote: sign: %w", err)
		}
		sigPath := path + ".jws"
		if err := os.WriteFile(sigPath, []byte(compact), 0o640); err != nil {
			return nil, fmt.Errorf("lote: write %s: %w", sigPath, err)
		}
		written = append(written, sigPath)
	}
	return written, nil
}

// KeySigner builds a JAdES-B-B signer over any crypto.Signer, so a LoTE can be
// signed by a key on a PKCS#11 token as readily as by one in a file.
func KeySigner(key crypto.Signer, chain []*x509.Certificate) (Signer, error) {
	if key == nil {
		return nil, fmt.Errorf("lote: no signing key")
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("lote: no signing certificate chain")
	}
	return &keySigner{key: key, chain: chain}, nil
}

type keySigner struct {
	key   crypto.Signer
	chain []*x509.Certificate
}

func (s *keySigner) Sign(payload []byte) (string, error) {
	return sirosjws.SignJAdES(payload, s.key, s.chain)
}

func names(v string) etsi119602.NameSet {
	return etsi119602.NameSet{{Lang: "en", Value: v}}
}

// Signer is the signing interface Publish accepts. It matches g119612's
// jws.JSONSigner, so a signer from either source can be passed in.
type Signer interface {
	Sign(payload []byte) (string, error)
}
