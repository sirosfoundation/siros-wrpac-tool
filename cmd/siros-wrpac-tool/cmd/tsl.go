package cmd

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/sirosfoundation/siros-wrpac-tool/pkg/store"
	"github.com/sirosfoundation/siros-wrpac-tool/pkg/tsl"
)

var tslOpts struct {
	out          string
	sequence     int
	territory    string
	operator     string
	schemeName   string
	distribution string
	tslType      string
	nextUpdate   time.Duration
	sign         bool
}

var tslCmd = &cobra.Command{
	Use:   "tsl",
	Short: "Publish the deployment's trust anchors as an ETSI TS 119 612 TSL",
	Long: `tsl writes a Trust Status List naming this deployment's Access CA and
registration certificate provider — the same statement the lote command makes,
in the XML format that existing eIDAS trusted-list consumers already read.

Publish both if you do not know what will consume them: 'lote' produces the
newer TS 119 602 JSON list the EUDI wallet ecosystem is moving to, this produces
the TS 119 612 XML list everything else speaks.

Unlike the LoTE this writes a single file: the XMLDSig signature is enveloped in
the document rather than detached beside it.

The sequence number must increase on every republication; --sequence defaults to
the deployment's CRL number, which already advances on every change.`,
	RunE: runTSL,
}

func runTSL(_ *cobra.Command, _ []string) error {
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
	dist := tslOpts.distribution
	if dist == "" {
		dist = base + "/tsl.xml"
	}
	seq := tslOpts.sequence
	if seq == 0 {
		// Same counter the LoTE uses, for the same reason: it already advances
		// on every change and is already persisted.
		seq = s.Register.CRLNumber
		if seq == 0 {
			seq = 1
		}
	}

	list, err := tsl.Build([]tsl.Entity{
		{
			Name:              caCert.Subject.CommonName,
			ServiceType:       tsl.ServiceTypeAccessCA,
			Certificate:       caCert,
			InformationURI:    base,
			ElectronicAddress: base + "/support",
		},
		{
			Name:              regCert.Subject.CommonName,
			ServiceType:       tsl.ServiceTypeRegistrationCertProvider,
			Certificate:       regCert,
			InformationURI:    base + "/registrar",
			ElectronicAddress: base + "/support",
		},
	}, tsl.Options{
		SequenceNumber:    seq,
		Territory:         tslOpts.territory,
		OperatorName:      tslOpts.operator,
		SchemeName:        tslOpts.schemeName,
		DistributionPoint: dist,
		InformationURI:    base,
		ElectronicAddress: base + "/support",
		NextUpdate:        tslOpts.nextUpdate,
		TSLType:           tslOpts.tslType,
	})
	if err != nil {
		return err
	}

	var signer *tsl.Signer
	if tslOpts.sign {
		// The registrar signs the list, as it does the LoTE: using the CA key
		// would mean the same key both anchors the list and appears inside it.
		resolved, rerr := s.RegistrarKeyRef().Resolve()
		if rerr != nil {
			return rerr
		}
		defer func() { _ = resolved.Close() }()

		signer, err = tsl.NewSigner(resolved.Signer, []*x509.Certificate{regCert, caCert})
		if err != nil {
			return err
		}
	}

	outDir := tslOpts.out
	if outDir == "" {
		outDir = s.PublicDir()
	}
	written, err := tsl.Publish(list, outDir, signer)
	if err != nil {
		return err
	}

	fmt.Printf("published TSL sequence %d\n", seq)
	for _, p := range written {
		fmt.Printf("  %s\n", p)
	}
	fmt.Printf("\nconfigure this as a trusted list source for an ETSI TS 119 612 consumer.\n")
	return nil
}

func init() {
	addDirFlag(tslCmd)
	f := tslCmd.Flags()
	f.StringVar(&tslOpts.out, "out", "", "output directory (default: the deployment's public/)")
	f.IntVar(&tslOpts.sequence, "sequence", 0, "TSL sequence number (default: the deployment's CRL number)")
	f.StringVar(&tslOpts.territory, "territory", "SE", "ISO 3166-1 alpha-2 scheme territory")
	f.StringVar(&tslOpts.operator, "operator", "SIROS Foundation", "scheme operator name")
	f.StringVar(&tslOpts.schemeName, "scheme-name", "SIROS wallet-relying party trust anchors", "scheme name")
	f.StringVar(&tslOpts.distribution, "distribution-point", "", "URL this list is published at; also sets the filename")
	f.StringVar(&tslOpts.tslType, "tsl-type", "", "TSLType URI (default: the generic, non-eIDAS-supervised type)")
	f.DurationVar(&tslOpts.nextUpdate, "next-update", 90*24*time.Hour, "how long the list claims to be current")
	f.BoolVar(&tslOpts.sign, "sign", true, "sign the list with the registration certificate provider key")
	rootCmd.AddCommand(tslCmd)
}
