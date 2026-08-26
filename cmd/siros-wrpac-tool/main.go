// Command siros-wrpac-tool mints the access and registration certificates that
// authenticate a wallet-relying party — verifier or issuer — to an EUDI Wallet.
package main

import (
	"fmt"
	"os"

	"github.com/sirosfoundation/siros-wrpac-tool/cmd/siros-wrpac-tool/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
