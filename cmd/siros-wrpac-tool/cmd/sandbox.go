package cmd

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/sirosfoundation/siros-wrpac-tool/pkg/wrpac"
	"github.com/sirosfoundation/siros-wrpac-tool/pkg/wrprc"
)

var sandboxOpts struct {
	outDir      string
	baseURL     string
	issuerName  string
	issuerOrg   string
	identifier  string
	country     string
	entitlement string
	vct         string
	docType     string
}

var sandboxCmd = &cobra.Command{
	Use:   "sandbox",
	Short: "Mint a complete test set: Access CA, WRPAC, WRPRC and CRL",
	Long: `sandbox produces everything needed to exercise issuer-side access and
registration certificate handling end to end:

  ca.pem            Access CA certificate (the trust anchor to configure)
  ca.key            Access CA private key
  wrpac.pem         the relying party's access certificate
  wrpac.key         its private key — sign Issuer Metadata with this
  crl.der           an empty CRL, published so "nothing revoked" is sayable
  wrprc.jwt         the registration certificate (rc-wrp+jwt)
  registrar.pem     the registration certificate provider's certificate

The WRPRC carries a provider entitlement and a provides_attestations entry, so a
wallet can check both that the subject may issue and that it registered the
attestation type it is offering.`,
	RunE: runSandbox,
}

func init() {
	f := sandboxCmd.Flags()
	f.StringVar(&sandboxOpts.outDir, "out", "out", "output directory")
	f.StringVar(&sandboxOpts.baseURL, "base-url", "https://issuer.example.org", "base URL of the relying party")
	f.StringVar(&sandboxOpts.issuerName, "name", "Example Attestation Provider", "trade name")
	f.StringVar(&sandboxOpts.issuerOrg, "organization", "Example Provider GmbH", "registered legal name")
	f.StringVar(&sandboxOpts.identifier, "identifier", "LEIXG-529900T8BM49AURSDO55", "EU-wide unique WRP identifier (EN 319 412-1 semantic form)")
	f.StringVar(&sandboxOpts.country, "country", "DE", "ISO 3166-1 alpha-2 country of establishment")
	f.StringVar(&sandboxOpts.entitlement, "entitlement", wrprc.EntitlementPIDProvider, "provider entitlement URI")
	f.StringVar(&sandboxOpts.vct, "vct", "urn:eudi:pid:1", "vct value for the registered SD-JWT attestation")
	f.StringVar(&sandboxOpts.docType, "doctype", "eu.europa.ec.eudi.pid.1", "doctype for the registered mdoc attestation")
	rootCmd.AddCommand(sandboxCmd)
}

func runSandbox(_ *cobra.Command, _ []string) error {
	out := sandboxOpts.outDir
	if err := os.MkdirAll(out, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	crlDP := sandboxOpts.baseURL + "/status-management/crl"

	ca, err := wrpac.NewCA(wrpac.CAOptions{
		CommonName:           "Sandbox Access CA",
		Organization:         "SIROS Foundation",
		Country:              sandboxOpts.country,
		CRLDistributionPoint: crlDP,
	})
	if err != nil {
		return err
	}
	if err = writeCert(filepath.Join(out, "ca.pem"), ca.Certificate); err != nil {
		return err
	}
	if err = writeKey(filepath.Join(out, "ca.key"), ca.Key); err != nil {
		return err
	}

	issued, err := ca.Issue(wrpac.Request{
		Kind:         wrpac.LegalPerson,
		Level:        wrpac.Normalised,
		CommonName:   sandboxOpts.issuerName,
		Organization: sandboxOpts.issuerOrg,
		Country:      sandboxOpts.country,
		Identifier:   sandboxOpts.identifier,
		SupportURI:   sandboxOpts.baseURL + "/support",
		Email:        "support@example.org",
	})
	if err != nil {
		return err
	}
	if err = writeCert(filepath.Join(out, "wrpac.pem"), issued.Certificate); err != nil {
		return err
	}
	if err = writeKey(filepath.Join(out, "wrpac.key"), issued.Key); err != nil {
		return err
	}

	crl, err := ca.CreateCRL(nil, time.Now().UTC(), 30*24*time.Hour)
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(out, "crl.der"), crl, 0o644); err != nil {
		return fmt.Errorf("write CRL: %w", err)
	}

	// The registration certificate provider is a separate trust service from the
	// Access CA, so it gets its own certificate rather than reusing the WRPAC.
	registrar, err := ca.Issue(wrpac.Request{
		Kind:         wrpac.LegalPerson,
		Level:        wrpac.Normalised,
		CommonName:   "Sandbox Registration Certificate Provider",
		Organization: "SIROS Foundation",
		Country:      sandboxOpts.country,
		Identifier:   "NTRDE-SANDBOX-REGISTRAR",
		SupportURI:   sandboxOpts.baseURL + "/registrar",
	})
	if err != nil {
		return err
	}
	if err = writeCert(filepath.Join(out, "registrar.pem"), registrar.Certificate); err != nil {
		return err
	}

	signer := &wrprc.Signer{Chain: []*x509.Certificate{registrar.Certificate, ca.Certificate}, Key: registrar.Key}
	token, err := signer.Mint(wrprc.Payload{
		Name:         sandboxOpts.issuerName,
		Sub:          sandboxOpts.identifier,
		SubLegalName: sandboxOpts.issuerOrg,
		Country:      sandboxOpts.country,
		RegistryURI:  sandboxOpts.baseURL + "/registrar",
		Entitlements: []string{sandboxOpts.entitlement},
		ProvidesAttestations: []wrprc.Credential{
			{Format: "dc+sd-jwt", Meta: map[string]any{"vct_values": []string{sandboxOpts.vct}}},
			{Format: "mso_mdoc", Meta: map[string]any{"doctype_value": sandboxOpts.docType}},
		},
		SupportURI:        sandboxOpts.baseURL + "/support",
		CertificatePolicy: sandboxOpts.baseURL + "/certificate-policy",
		Status: &wrprc.Status{StatusList: wrprc.StatusList{
			Idx: 0,
			URI: sandboxOpts.baseURL + "/api/status-management/status-list",
		}},
	})
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(out, "wrprc.jwt"), []byte(token+"\n"), 0o644); err != nil {
		return fmt.Errorf("write WRPRC: %w", err)
	}

	fmt.Printf("wrote sandbox material to %s\n", out)
	fmt.Printf("  access CA        %s\n", ca.Certificate.Subject.CommonName)
	fmt.Printf("  WRPAC subject    %s (%s)\n", issued.Certificate.Subject.CommonName, sandboxOpts.identifier)
	fmt.Printf("  WRPAC policy     %v\n", issued.Certificate.Policies)
	fmt.Printf("  WRPRC entitlement %s\n", sandboxOpts.entitlement)
	return nil
}

func writeCert(path string, cert *x509.Certificate) error {
	b := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// writeKey writes a private key with 0600 permissions. These are test keys, but
// a tool that mints them should not be the reason a key ends up world-readable.
func writeKey(path string, key crypto.Signer) error {
	priv, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return fmt.Errorf("write %s: expected an ECDSA key, got %T", path, key)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}
	b := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
