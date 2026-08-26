package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Build metadata, injected via -ldflags.
var (
	Version   = "dev"
	Commit    = "none"
	BuildTime = "unknown"
)

var rootCmd = &cobra.Command{
	Use:   "siros-wrpac-tool",
	Short: "Registrar and Access CA for EUDI wallet-relying party certificates",
	Long: `siros-wrpac-tool issues the two certificates that identify a wallet-relying
party to an EUDI Wallet:

  - a Wallet-Relying Party Access Certificate (WRPAC), an X.509 certificate
    following the ETSI TS 119 411-8 profile; and
  - a Wallet-Relying Party Registration Certificate (WRPRC), a signed JWT
    following ETSI TS 119 475 V1.2.1.

Both apply to issuers as well as verifiers: under CIR (EU) 2025/848 a PID
Provider or Attestation Provider is a registered wallet-relying party, and per
ETSI TS 119 472-3 its WRPAC signs its OpenID4VCI Issuer Metadata.

This is development and test tooling. It is not a supervised trust service and
the certificates it mints have no standing outside a test ecosystem.`,
	SilenceUsage: true,
}

// Execute runs the root command.
func Execute() error { return rootCmd.Execute() }

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(_ *cobra.Command, _ []string) {
		fmt.Printf("siros-wrpac-tool %s (commit: %s, built: %s)\n", Version, Commit, BuildTime)
	},
}

func init() { rootCmd.AddCommand(versionCmd) }
