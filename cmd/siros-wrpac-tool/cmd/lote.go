package cmd

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/sirosfoundation/siros-wrpac-tool/pkg/lote"
	"github.com/sirosfoundation/siros-wrpac-tool/pkg/store"
)

var loteOpts struct {
	out          string
	sequence     int
	territory    string
	operator     string
	schemeName   string
	distribution string
	infoURI      string
	nextUpdate   time.Duration
	sign         bool
}

var loteCmd = &cobra.Command{
	Use:   "lote",
	Short: "Publish the deployment's trust anchors as an ETSI TS 119 602 LoTE",
	Long: `lote writes a List of Trusted Entities naming this deployment's Access CA and
registration certificate provider, so a wallet can be configured to trust what
this tool issues.

The document is built with g119612's own types and written in the layout its
publish-lote pipeline step produces — the unsigned JSON, plus a compact JWS
alongside it when signing. Output therefore drops straight into a tsl-tool
pipeline directory, and go-trust's pkg/registry/lote consumes it as-is.

The sequence number must increase on every republication; --sequence defaults to
the deployment's CRL number, which already advances on every change.`,
	RunE: runLoTE,
}

func runLoTE(_ *cobra.Command, _ []string) error {
	s, err := store.Open(deployDir)
	if err != nil {
		return err
	}
	caCert, err := store.ReadCert(s.CACertPath())
	if err != nil {
		return err
	}
	regCert, err := store.ReadCert(s.RegistrarCertPath())
	if err != nil {
		return err
	}

	base := s.Register.BaseURL
	dist := loteOpts.distribution
	if dist == "" {
		dist = base + "/lote.json"
	}
	seq := loteOpts.sequence
	if seq == 0 {
		// Reuse the CRL number rather than inventing a second counter: it already
		// advances on every change and is already persisted.
		seq = s.Register.CRLNumber
		if seq == 0 {
			seq = 1
		}
	}

	list, err := lote.Build([]lote.Entity{
		{
			Name:              caCert.Subject.CommonName,
			ServiceType:       lote.ServiceTypeAccessCA,
			Certificate:       caCert,
			InformationURI:    base,
			ElectronicAddress: base + "/support",
		},
		{
			Name:              regCert.Subject.CommonName,
			ServiceType:       lote.ServiceTypeRegistrationCertProvider,
			Certificate:       regCert,
			InformationURI:    base + "/registrar",
			ElectronicAddress: base + "/support",
		},
	}, lote.Options{
		SequenceNumber:    seq,
		Territory:         loteOpts.territory,
		OperatorName:      loteOpts.operator,
		SchemeName:        loteOpts.schemeName,
		DistributionPoint: dist,
		InformationURI:    base,
		NextUpdate:        loteOpts.nextUpdate,
	})
	if err != nil {
		return err
	}

	var signer lote.Signer
	if loteOpts.sign {
		// The registrar signs the list. It is the deployment's publishing trust
		// service, and using the CA key here would mean the same key both anchors
		// the list and appears inside it.
		signer, err = lote.FileSigner(s.RegistrarCertPath(), s.RegistrarKeyPath())
		if err != nil {
			return err
		}
	}

	outDir := loteOpts.out
	if outDir == "" {
		outDir = s.PublicDir()
	}
	written, err := lote.Publish(list, outDir, signer)
	if err != nil {
		return err
	}

	fmt.Printf("published LoTE sequence %d\n", seq)
	for _, p := range written {
		fmt.Printf("  %s\n", p)
	}
	fmt.Printf("\nconfigure this as a LoTE source for go-trust's pkg/registry/lote.\n")
	return nil
}

func init() {
	addDirFlag(loteCmd)
	f := loteCmd.Flags()
	f.StringVar(&loteOpts.out, "out", "", "output directory (default: the deployment's public/)")
	f.IntVar(&loteOpts.sequence, "sequence", 0, "LoTE sequence number (default: the deployment's CRL number)")
	f.StringVar(&loteOpts.territory, "territory", "SE", "ISO 3166-1 alpha-2 scheme territory")
	f.StringVar(&loteOpts.operator, "operator", "SIROS Foundation", "scheme operator name")
	f.StringVar(&loteOpts.schemeName, "scheme-name", "SIROS wallet-relying party trust anchors", "scheme name")
	f.StringVar(&loteOpts.distribution, "distribution-point", "", "URL this list is published at; also sets the filename")
	f.DurationVar(&loteOpts.nextUpdate, "next-update", 90*24*time.Hour, "how long the list claims to be current")
	f.BoolVar(&loteOpts.sign, "sign", true, "sign the list with the registration certificate provider key")
	rootCmd.AddCommand(loteCmd)
}
