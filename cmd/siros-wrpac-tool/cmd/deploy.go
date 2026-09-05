package cmd

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sirosfoundation/siros-wrpac-tool/pkg/keyref"
	"github.com/sirosfoundation/siros-wrpac-tool/pkg/statuslist"
	"github.com/sirosfoundation/siros-wrpac-tool/pkg/store"
	"github.com/sirosfoundation/siros-wrpac-tool/pkg/wrpac"
	"github.com/sirosfoundation/siros-wrpac-tool/pkg/wrprc"
)

// Relative paths under public/, and the URL paths that mirror them.
const (
	crlFile        = "crl.der"
	statusListFile = "status-list.jwt"
	registerFile   = "register.json"
)

var deployDir string

func addDirFlag(c *cobra.Command) {
	c.Flags().StringVarP(&deployDir, "dir", "d", "deployment", "deployment directory")
}

// ---------------------------------------------------------------- init

var initOpts struct {
	pkcs11Module string
	pkcs11Token  string
	pkcs11Slot   uint
	pkcs11PINEnv string
	caKeyLabel   string
	regKeyLabel  string

	baseURL            string
	caName             string
	regName            string
	org                string
	country            string
	validity           time.Duration
	crlValidity        time.Duration
	statusListValidity time.Duration
}

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Create a deployment: Access CA and registration certificate provider",
	Long: `init creates a deployment directory holding the two trust services this tool
operates: an Access CA that signs WRPACs, and a provider of registration
certificates that signs WRPRCs.

Both keys are generated once and must then be preserved. Re-running init against
an existing directory is refused, because replacing a CA key silently
invalidates every certificate that chains to it.`,
	RunE: runInit,
}

func runInit(_ *cobra.Command, _ []string) error {
	s, err := store.Create(deployDir, strings.TrimSuffix(initOpts.baseURL, "/"))
	if err != nil {
		return err
	}

	// With PKCS#11 the keys already exist on the token — this tool certifies
	// them, it does not create them. Generate an operator's keys with
	// pkcs11-tool or the HSM's own tooling first.
	caRef, regRef, err := initKeyRefs()
	if err != nil {
		return err
	}

	var caKey crypto.Signer
	if caRef.IsPKCS11() {
		resolved, rerr := caRef.Resolve()
		if rerr != nil {
			return rerr
		}
		defer func() { _ = resolved.Close() }()
		caKey = resolved.Signer
	}

	ca, err := wrpac.NewCA(wrpac.CAOptions{
		Key:                  caKey,
		CommonName:           initOpts.caName,
		Organization:         initOpts.org,
		Country:              initOpts.country,
		Validity:             initOpts.validity,
		CRLDistributionPoint: s.Register.BaseURL + "/" + crlFile,
	})
	if err != nil {
		return err
	}
	if err = store.WriteCert(s.CACertPath(), ca.Certificate); err != nil {
		return err
	}
	if !caRef.IsPKCS11() {
		if err = store.WriteKey(s.CAKeyPath(), mustECDSA(ca.Key)); err != nil {
			return err
		}
	}

	var regKey crypto.Signer
	if regRef.IsPKCS11() {
		resolved, rerr := regRef.Resolve()
		if rerr != nil {
			return rerr
		}
		defer func() { _ = resolved.Close() }()
		regKey = resolved.Signer
	}

	// The registration certificate provider is a distinct trust service under
	// CIR 2025/848, so it gets its own key rather than reusing the CA's.
	registrar, err := ca.Issue(wrpac.Request{
		Key:          regKey,
		Kind:         wrpac.LegalPerson,
		Level:        wrpac.Normalised,
		CommonName:   initOpts.regName,
		Organization: initOpts.org,
		Country:      initOpts.country,
		Identifier:   "NTR" + initOpts.country + "-REGISTRAR",
		SupportURI:   s.Register.BaseURL + "/registrar",
		Validity:     initOpts.validity,
	})
	if err != nil {
		return err
	}
	if err = store.WriteCert(s.RegistrarCertPath(), registrar.Certificate); err != nil {
		return err
	}
	if !regRef.IsPKCS11() {
		if err = store.WriteKey(s.RegistrarKeyPath(), mustECDSA(registrar.Key)); err != nil {
			return err
		}
	}

	s.Register.CAKey = caRef
	s.Register.RegistrarKey = regRef
	s.Register.CRLValidity = initOpts.crlValidity.String()
	s.Register.StatusListValidity = initOpts.statusListValidity.String()
	if err = s.Save(); err != nil {
		return err
	}
	if err = publish(s); err != nil {
		return err
	}

	fmt.Printf("initialised deployment in %s\n", s.Dir)
	fmt.Printf("  base URL   %s\n", s.Register.BaseURL)
	fmt.Printf("  access CA  %s\n", ca.Certificate.Subject.CommonName)
	fmt.Printf("    key      %s\n", caRef.Describe())
	fmt.Printf("  registrar  %s\n", registrar.Certificate.Subject.CommonName)
	fmt.Printf("    key      %s\n", regRef.Describe())
	fmt.Printf("\nconfigure %s as the Access CA trust anchor.\n", s.CACertPath())
	return nil
}

// initKeyRefs decides where this deployment's two keys live. Without
// --pkcs11-module both are files inside the deployment; with it, both are on the
// token and nothing private is ever written to disk.
func initKeyRefs() (caRef, regRef keyref.Ref, err error) {
	if initOpts.pkcs11Module == "" {
		return keyref.Ref{File: filepath.Join(deployDir, "ca.key")},
			keyref.Ref{File: filepath.Join(deployDir, "registrar.key")}, nil
	}
	if initOpts.caKeyLabel == "" || initOpts.regKeyLabel == "" {
		return caRef, regRef, fmt.Errorf("init: --ca-key-label and --registrar-key-label are required with --pkcs11-module")
	}
	base := keyref.PKCS11{
		Module:     initOpts.pkcs11Module,
		TokenLabel: initOpts.pkcs11Token,
		SlotID:     initOpts.pkcs11Slot,
		PINEnv:     initOpts.pkcs11PINEnv,
	}
	caPK, regPK := base, base
	caPK.KeyLabel = initOpts.caKeyLabel
	regPK.KeyLabel = initOpts.regKeyLabel
	return keyref.Ref{PKCS11: &caPK}, keyref.Ref{PKCS11: &regPK}, nil
}

// ---------------------------------------------------------------- issue

var issueOpts struct {
	name         string
	organization string
	identifier   string
	country      string
	supportURI   string
	email        string
	entitlements []string
	vct          []string
	doctype      []string
	validity     time.Duration
	natural      bool
	qualified    bool
	out          string
}

var issueCmd = &cobra.Command{
	Use:   "issue",
	Short: "Register a wallet-relying party and issue its WRPAC and WRPRC",
	Long: `issue registers a wallet-relying party in the deployment's register and mints
both of its certificates.

Use --entitlement more than once for a party holding several roles. A provider
entitlement (PID_Provider, QEAA_Provider, Non_Q_EAA_Provider, PUB_EAA_Provider)
allows --vct and --doctype, which become the provides_attestations entry
declaring what the party is registered to issue.`,
	RunE: runIssue,
}

func runIssue(_ *cobra.Command, _ []string) error {
	s, err := store.Open(deployDir)
	if err != nil {
		return err
	}
	ca, closeCA, err := loadCA(s)
	if err != nil {
		return err
	}
	defer func() { _ = closeCA() }()

	kind := wrpac.LegalPerson
	if issueOpts.natural {
		kind = wrpac.NaturalPerson
	}
	level := wrpac.Normalised
	if issueOpts.qualified {
		level = wrpac.Qualified
	}

	supportURI := issueOpts.supportURI
	if supportURI == "" && issueOpts.email == "" {
		return fmt.Errorf("issue: --support-uri or --email is required (subjectAltName must carry a contact)")
	}

	issued, err := ca.Issue(wrpac.Request{
		Kind:         kind,
		Level:        level,
		CommonName:   issueOpts.name,
		Organization: issueOpts.organization,
		Country:      issueOpts.country,
		Identifier:   issueOpts.identifier,
		SupportURI:   supportURI,
		Email:        issueOpts.email,
		Validity:     issueOpts.validity,
	})
	if err != nil {
		return err
	}

	serial := fmt.Sprintf("%x", issued.Certificate.SerialNumber)
	entry := &store.Entry{
		Serial:       serial,
		Identifier:   issueOpts.identifier,
		Name:         issueOpts.name,
		Entitlements: issueOpts.entitlements,
		StatusIndex:  s.AllocateStatusIndex(),
		IssuedAt:     issued.Certificate.NotBefore,
		NotAfter:     issued.Certificate.NotAfter,
	}
	s.Register.Entries[serial] = entry

	if err = store.WriteCert(s.IssuedPath(serial), issued.Certificate); err != nil {
		return err
	}

	token, err := mintWRPRC(s, entry)
	if err != nil {
		return err
	}

	outDir := issueOpts.out
	if outDir == "" {
		outDir = filepath.Join(s.Dir, "issued", serial+".d")
	}
	if err = os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("issue: create %s: %w", outDir, err)
	}
	if err = store.WriteCert(filepath.Join(outDir, "wrpac.pem"), issued.Certificate); err != nil {
		return err
	}
	if err = store.WriteKey(filepath.Join(outDir, "wrpac.key"), mustECDSA(issued.Key)); err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(outDir, "wrprc.jwt"), []byte(token+"\n"), 0o644); err != nil {
		return fmt.Errorf("issue: write WRPRC: %w", err)
	}

	if err = s.Save(); err != nil {
		return err
	}
	if err = publish(s); err != nil {
		return err
	}

	fmt.Printf("issued %s\n", issueOpts.name)
	fmt.Printf("  serial        %s\n", serial)
	fmt.Printf("  identifier    %s\n", issueOpts.identifier)
	fmt.Printf("  entitlements  %s\n", strings.Join(issueOpts.entitlements, ", "))
	fmt.Printf("  status index  %d\n", entry.StatusIndex)
	fmt.Printf("  material      %s\n", outDir)
	return nil
}

// mintWRPRC builds the registration certificate for a register entry.
func mintWRPRC(s *store.Store, e *store.Entry) (string, error) {
	regCert, err := store.ReadCert(s.RegistrarCertPath())
	if err != nil {
		return "", err
	}
	regResolved, err := s.RegistrarKeyRef().Resolve()
	if err != nil {
		return "", err
	}
	defer func() { _ = regResolved.Close() }()
	caCert, err := store.ReadCert(s.CACertPath())
	if err != nil {
		return "", err
	}

	var provides []wrprc.Credential
	for _, v := range issueOpts.vct {
		provides = append(provides, wrprc.Credential{
			Format: "dc+sd-jwt", Meta: map[string]any{"vct_values": []string{v}},
		})
	}
	for _, d := range issueOpts.doctype {
		provides = append(provides, wrprc.Credential{
			Format: "mso_mdoc", Meta: map[string]any{"doctype_value": d},
		})
	}

	signer := &wrprc.Signer{Chain: []*x509.Certificate{regCert, caCert}, Key: regResolved.Signer}
	return signer.Mint(wrprc.Payload{
		Name:                 e.Name,
		Sub:                  e.Identifier,
		SubLegalName:         issueOpts.organization,
		Country:              issueOpts.country,
		RegistryURI:          s.Register.BaseURL + "/" + registerFile,
		Entitlements:         e.Entitlements,
		ProvidesAttestations: provides,
		SupportURI:           issueOpts.supportURI,
		CertificatePolicy:    s.Register.BaseURL + "/certificate-policy",
		Status: &wrprc.Status{StatusList: wrprc.StatusList{
			Idx: e.StatusIndex,
			URI: s.Register.BaseURL + "/" + statusListFile,
		}},
	})
}

// ---------------------------------------------------------------- revoke

var revokeReason int

var revokeCmd = &cobra.Command{
	Use:   "revoke <serial>",
	Short: "Revoke a registration and republish the CRL and status list",
	Long: `revoke suspends or cancels a registered party. Both revocation mechanisms are
updated together: the WRPAC goes on the CRL and the WRPRC's status list bit is
set. Revoking only one leaves the party usable through the other.`,
	Args: cobra.ExactArgs(1),
	RunE: runRevoke,
}

func runRevoke(_ *cobra.Command, args []string) error {
	s, err := store.Open(deployDir)
	if err != nil {
		return err
	}
	entry, ok := s.Register.Entries[args[0]]
	if !ok {
		return fmt.Errorf("revoke: no entry with serial %s", args[0])
	}
	if entry.Revoked {
		fmt.Printf("%s is already revoked\n", args[0])
		return nil
	}
	now := time.Now().UTC()
	entry.Revoked = true
	entry.RevokedAt = &now
	entry.RevocationReason = revokeReason

	if err = s.Save(); err != nil {
		return err
	}
	if err = publish(s); err != nil {
		return err
	}
	fmt.Printf("revoked %s (%s)\n", entry.Name, args[0])
	fmt.Printf("  CRL and status list republished; status index %d is now set\n", entry.StatusIndex)
	return nil
}

// ---------------------------------------------------------------- publish

var publishCmd = &cobra.Command{
	Use:   "publish",
	Short: "Regenerate the CRL, status list and public register",
	RunE: func(_ *cobra.Command, _ []string) error {
		s, err := store.Open(deployDir)
		if err != nil {
			return err
		}
		if err = publish(s); err != nil {
			return err
		}
		fmt.Printf("published to %s\n", s.PublicDir())
		return nil
	},
}

// statusListTTL is the cache hint (ttl) in the status list token. It is
// independent of the token's validity: a consumer re-fetches this often and
// picks up a republished list, while exp bounds how long an old one may live.
const statusListTTL = time.Hour

// publish regenerates everything served from public/.
//
// It is called after every mutation rather than on demand: a register that has
// moved on while the CRL has not is worse than no CRL, because it looks current.
func publish(s *store.Store) error {
	ca, closeCA, err := loadCA(s)
	if err != nil {
		return err
	}
	defer func() { _ = closeCA() }()

	var revoked []x509.RevocationListEntry
	list := statuslist.New(maxInt(s.Register.NextStatusIndex, 8))
	for _, e := range s.Register.Entries {
		if !e.Revoked {
			continue
		}
		serial, ok := new(big.Int).SetString(e.Serial, 16)
		if !ok {
			return fmt.Errorf("publish: entry %q has an unparseable serial", e.Serial)
		}
		at := time.Now().UTC()
		if e.RevokedAt != nil {
			at = *e.RevokedAt
		}
		revoked = append(revoked, x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: at,
			ReasonCode:     e.RevocationReason,
		})
		if err = list.Revoke(e.StatusIndex); err != nil {
			return fmt.Errorf("publish: %w", err)
		}
	}

	crlValidity, err := s.CRLValidityDuration()
	if err != nil {
		return err
	}
	crl, err := ca.CreateCRL(revoked, time.Now().UTC(), crlValidity)
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(s.PublicDir(), crlFile), crl, 0o644); err != nil {
		return fmt.Errorf("publish: write CRL: %w", err)
	}

	regCert, err := store.ReadCert(s.RegistrarCertPath())
	if err != nil {
		return err
	}
	regResolved, err := s.RegistrarKeyRef().Resolve()
	if err != nil {
		return err
	}
	defer func() { _ = regResolved.Close() }()
	statusValidity, err := s.StatusListValidityDuration()
	if err != nil {
		return err
	}
	token, err := list.Sign(
		s.Register.BaseURL,
		s.Register.BaseURL+"/"+statusListFile,
		regResolved.Signer,
		[]*x509.Certificate{regCert, ca.Certificate},
		statusListTTL,
		statusValidity,
	)
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(s.PublicDir(), statusListFile), []byte(token+"\n"), 0o644); err != nil {
		return fmt.Errorf("publish: write status list: %w", err)
	}

	// The public register is the Annex II "publicly available online, in a form
	// suitable for automated processing" view. Private material stays out of it.
	pub := make([]map[string]any, 0, len(s.Register.Entries))
	for _, e := range s.Register.Entries {
		pub = append(pub, map[string]any{
			"serial":       e.Serial,
			"identifier":   e.Identifier,
			"name":         e.Name,
			"entitlements": e.Entitlements,
			"issued_at":    e.IssuedAt,
			"not_after":    e.NotAfter,
			"revoked":      e.Revoked,
		})
	}
	raw, err := json.MarshalIndent(map[string]any{"wallet_relying_parties": pub}, "", "  ")
	if err != nil {
		return fmt.Errorf("publish: marshal register: %w", err)
	}
	if err = os.WriteFile(filepath.Join(s.PublicDir(), registerFile), append(raw, '\n'), 0o644); err != nil {
		return fmt.Errorf("publish: write register: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------- list

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "Show the register",
	RunE: func(_ *cobra.Command, _ []string) error {
		s, err := store.Open(deployDir)
		if err != nil {
			return err
		}
		if len(s.Register.Entries) == 0 {
			fmt.Println("register is empty")
			return nil
		}
		// Serials are printed in full: this output is what an operator pastes
		// into `revoke`, so truncating it for width would make the command
		// unusable against its own listing.
		fmt.Printf("%-34s  %-32s  %-7s  %s\n", "SERIAL", "IDENTIFIER", "STATUS", "NAME")
		for _, e := range s.Register.Entries {
			status := "valid"
			if e.Revoked {
				status = "REVOKED"
			}
			fmt.Printf("%-34s  %-32s  %-7s  %s\n", e.Serial, e.Identifier, status, e.Name)
		}
		return nil
	},
}

// ---------------------------------------------------------------- helpers

// loadCA opens the CA, resolving its key wherever it lives. The returned close
// function releases a PKCS#11 session pool and is a no-op for file keys, so
// callers can always defer it.
func loadCA(s *store.Store) (*wrpac.CA, func() error, error) {
	cert, err := store.ReadCert(s.CACertPath())
	if err != nil {
		return nil, nil, err
	}
	resolved, err := s.CAKeyRef().Resolve()
	if err != nil {
		return nil, nil, err
	}
	return &wrpac.CA{
		Certificate:          cert,
		Key:                  resolved.Signer,
		CRLDistributionPoint: s.Register.BaseURL + "/" + crlFile,
	}, resolved.Close, nil
}

// mustECDSA narrows a crypto.Signer to the ECDSA key the store persists. Every
// key this tool generates is P-256, so a mismatch is a programming error rather
// than a runtime condition to report.
func mustECDSA(k crypto.Signer) *ecdsa.PrivateKey {
	priv, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		panic(fmt.Sprintf("expected an ECDSA key, got %T", k))
	}
	return priv
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func init() {
	addDirFlag(initCmd)
	f := initCmd.Flags()
	f.StringVar(&initOpts.baseURL, "base-url", "https://registrar.example.org", "public base URL where the CRL and status list are served")
	f.StringVar(&initOpts.caName, "ca-name", "SIROS Access CA", "Access CA common name")
	f.StringVar(&initOpts.regName, "registrar-name", "SIROS Registration Certificate Provider", "registration certificate provider common name")
	f.StringVar(&initOpts.org, "organization", "SIROS Foundation", "operator organization name")
	f.StringVar(&initOpts.country, "country", "SE", "ISO 3166-1 alpha-2 country")
	f.DurationVar(&initOpts.validity, "validity", 10*365*24*time.Hour, "CA validity")
	f.DurationVar(&initOpts.crlValidity, "crl-validity", store.DefaultRevocationValidity, "how long each published CRL stays valid; republish more often than this")
	f.DurationVar(&initOpts.statusListValidity, "status-list-validity", store.DefaultRevocationValidity, "how long each published status list token stays valid (exp); republish more often than this")
	f.StringVar(&initOpts.pkcs11Module, "pkcs11-module", "", "PKCS#11 shared library; keeps both keys on a token")
	f.StringVar(&initOpts.pkcs11Token, "pkcs11-token", "", "PKCS#11 token label (takes precedence over --pkcs11-slot)")
	f.UintVar(&initOpts.pkcs11Slot, "pkcs11-slot", 0, "PKCS#11 slot ID")
	f.StringVar(&initOpts.pkcs11PINEnv, "pkcs11-pin-env", "SIROS_WRPAC_PKCS11_PIN", "environment variable holding the user PIN; the PIN is never persisted")
	f.StringVar(&initOpts.caKeyLabel, "ca-key-label", "", "CKA_LABEL of the existing CA key on the token")
	f.StringVar(&initOpts.regKeyLabel, "registrar-key-label", "", "CKA_LABEL of the existing registrar key on the token")

	addDirFlag(issueCmd)
	g := issueCmd.Flags()
	g.StringVar(&issueOpts.name, "name", "", "trade name (required)")
	g.StringVar(&issueOpts.organization, "organization", "", "registered legal name (required for a legal person)")
	g.StringVar(&issueOpts.identifier, "identifier", "", "EU-wide unique identifier, EN 319 412-1 semantic form (required)")
	g.StringVar(&issueOpts.country, "country", "SE", "ISO 3166-1 alpha-2 country")
	g.StringVar(&issueOpts.supportURI, "support-uri", "", "support URL, becomes a subjectAltName URI")
	g.StringVar(&issueOpts.email, "email", "", "contact email, becomes a subjectAltName rfc822Name")
	g.StringArrayVar(&issueOpts.entitlements, "entitlement", []string{wrprc.EntitlementServiceProvider}, "entitlement URI; repeatable")
	g.StringArrayVar(&issueOpts.vct, "vct", nil, "SD-JWT vct this party is registered to issue; repeatable")
	g.StringArrayVar(&issueOpts.doctype, "doctype", nil, "mdoc doctype this party is registered to issue; repeatable")
	g.DurationVar(&issueOpts.validity, "validity", 365*24*time.Hour, "certificate validity")
	g.BoolVar(&issueOpts.natural, "natural-person", false, "use the natural person profile")
	g.BoolVar(&issueOpts.qualified, "qualified", false, "assert a qualified rather than normalised policy OID")
	g.StringVar(&issueOpts.out, "out", "", "directory for the issued material (default: inside the deployment)")
	_ = issueCmd.MarkFlagRequired("name")
	_ = issueCmd.MarkFlagRequired("identifier")

	addDirFlag(revokeCmd)
	revokeCmd.Flags().IntVar(&revokeReason, "reason", 0, "RFC 5280 CRLReason code")

	addDirFlag(publishCmd)
	addDirFlag(listCmd)

	rootCmd.AddCommand(initCmd, issueCmd, revokeCmd, publishCmd, listCmd)
}
