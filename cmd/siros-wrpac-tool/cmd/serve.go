package cmd

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/sirosfoundation/siros-wrpac-tool/pkg/statuslist"
	"github.com/sirosfoundation/siros-wrpac-tool/pkg/store"
	"github.com/sirosfoundation/siros-wrpac-tool/pkg/wrprc"
)

var serveOpts struct {
	addr string
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Serve the CRL, status list and public register over HTTP",
	Long: `serve publishes the deployment's public artefacts at the paths the issued
certificates point at:

  /crl.der          the Access CA's certificate revocation list
  /status-list.jwt  the registration certificate status list
  /register.json    the public register (CIR 2025/848 Annex II)
  /ca.pem           the Access CA certificate, for configuring trust anchors

Intended for small-scale deployments and interop testing. There is no TLS here:
put it behind a reverse proxy, because the base URL burned into every issued
certificate is https and a wallet will refuse to fetch over plain http.`,
	RunE: runServe,
}

// contentTypes maps a published file to the media type its consumer expects.
// Serving a status list as text/plain is the kind of thing that works in curl
// and fails in a wallet.
var contentTypes = map[string]string{
	crlFile:        "application/pkix-crl",
	statusListFile: "application/" + statuslist.MediaType,
	registerFile:   "application/json",
	"ca.pem":       "application/x-pem-file",
}

func runServe(_ *cobra.Command, _ []string) error {
	s, err := store.Open(deployDir)
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	for name := range contentTypes {
		mux.HandleFunc("/"+name, serveFile(s, name))
	}
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok\n"))
	})

	srv := &http.Server{
		Addr:              serveOpts.addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	fmt.Printf("serving %s on %s\n", s.PublicDir(), serveOpts.addr)
	for name := range contentTypes {
		fmt.Printf("  /%s\n", name)
	}
	fmt.Printf("\nissued certificates reference %s — make that resolve here.\n", s.Register.BaseURL)

	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

// serveFile serves one published artefact, re-reading it per request so that a
// concurrent `issue` or `revoke` is visible without restarting the server.
func serveFile(s *store.Store, name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		path := filepath.Join(s.PublicDir(), name)
		if name == "ca.pem" {
			path = s.CACertPath()
		}
		body, err := os.ReadFile(path)
		if err != nil {
			http.Error(w, "not published", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", contentTypes[name])
		// Short cache lifetimes on revocation data: a cached CRL outliving its
		// nextUpdate is how a revoked certificate keeps being accepted.
		w.Header().Set("Cache-Control", "public, max-age=300")
		if _, err := w.Write(body); err != nil {
			return
		}
	}
}

// ---------------------------------------------------------------- entitlements

var entitlementsCmd = &cobra.Command{
	Use:   "entitlements",
	Short: "List the TS 119 475 entitlement URIs accepted by --entitlement",
	Run: func(_ *cobra.Command, _ []string) {
		all := []struct {
			uri, desc string
		}{
			{wrprc.EntitlementServiceProvider, "general service provider"},
			{wrprc.EntitlementQEAAProvider, "qualified EAA provider"},
			{wrprc.EntitlementNonQEAAProvider, "non-qualified EAA provider"},
			{wrprc.EntitlementPUBEAAProvider, "public sector body EAA provider"},
			{wrprc.EntitlementPIDProvider, "person identification data provider"},
			{wrprc.EntitlementQCertForESealProvider, "QTSP issuing qualified eSeal certificates"},
			{wrprc.EntitlementQCertForESigProvider, "QTSP issuing qualified eSignature certificates"},
			{wrprc.EntitlementRQSealCDsProvider, "QTSP managing remote eSeal creation devices"},
			{wrprc.EntitlementRQSigCDsProvider, "QTSP managing remote eSignature creation devices"},
			{wrprc.EntitlementESigESealCreationProvider, "non-qualified remote signature/seal creation"},
		}
		for _, e := range all {
			marker := " "
			if wrprc.IsProviderEntitlement(e.uri) {
				marker = "*"
			}
			fmt.Printf("%s %-64s  %s\n", marker, e.uri, e.desc)
		}
		fmt.Println("\n* may carry provides_attestations (--vct / --doctype)")
	},
}

func init() {
	addDirFlag(serveCmd)
	serveCmd.Flags().StringVar(&serveOpts.addr, "addr", ":8080", "listen address")
	rootCmd.AddCommand(serveCmd, entitlementsCmd)
}
