package cmd

import (
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/spf13/cobra"

	"github.com/sirosfoundation/siros-wrpac-tool/pkg/clientspec"
	"github.com/sirosfoundation/siros-wrpac-tool/pkg/store"
	"github.com/sirosfoundation/siros-wrpac-tool/pkg/wrpac"
	"github.com/sirosfoundation/siros-wrpac-tool/pkg/wrprc"
)

var applyOpts struct {
	from   string
	out    string
	dryRun bool
	prune  bool
}

var applyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Reconcile the deployment against a directory of client specs",
	Long: `apply makes the deployment match a directory of per-client YAML files, which is
intended to live in git.

Each spec names a certificate signing request. The deployment certifies the
public key in it and never holds the private half, so neither the repository nor
the deployment stores a client secret.

Reconciliation is by client id — the 'id' field, defaulting to the filename stem.
Changing anything that affects the issued certificate re-issues it and revokes
the one it replaces. Setting 'revoked: true' revokes.

Deleting a spec file does NOT revoke unless --prune is given. Revocation is
close to irreversible, and an accidentally deleted file should not take a
production relying party out of service.

Run with --dry-run first; it prints the plan and changes nothing.`,
	RunE: runApply,
}

// action is one reconciliation step.
type action struct {
	kind   string // issue, reissue, revoke, unchanged
	id     string
	reason string
	spec   *clientspec.Spec
	entry  *store.Entry
}

func runApply(_ *cobra.Command, _ []string) error {
	s, err := store.Open(deployDir)
	if err != nil {
		return err
	}
	specs, err := clientspec.Load(applyOpts.from)
	if err != nil {
		return err
	}

	plan := buildPlan(s, specs)
	printPlan(plan)

	if applyOpts.dryRun {
		fmt.Println("\ndry run — nothing changed")
		return nil
	}
	if !hasWork(plan) {
		return nil
	}

	ca, closeCA, err := loadCA(s)
	if err != nil {
		return err
	}
	defer func() { _ = closeCA() }()

	for _, a := range plan {
		switch a.kind {
		case "issue", "reissue":
			if err := applyIssue(s, ca, a); err != nil {
				return err
			}
		case "revoke":
			revokeEntry(a.entry, a.spec)
		}
	}

	if err := s.Save(); err != nil {
		return err
	}
	if err := publish(s); err != nil {
		return err
	}
	fmt.Printf("\napplied; register and revocation data republished\n")
	return nil
}

// buildPlan diffs the specs against the register.
func buildPlan(s *store.Store, specs []*clientspec.Spec) []action {
	var plan []action
	inSpec := map[string]bool{}

	for _, spec := range specs {
		inSpec[spec.ID] = true
		entry := s.ActiveByClient(spec.ID)

		switch {
		case entry == nil && spec.Revoked:
			// Nothing to revoke, and issuing something already marked revoked
			// would put a dead certificate into circulation.
			plan = append(plan, action{kind: "unchanged", id: spec.ID, reason: "revoked and never issued", spec: spec})
		case entry == nil:
			plan = append(plan, action{kind: "issue", id: spec.ID, reason: "not yet issued", spec: spec})
		case spec.Revoked && !entry.Revoked:
			plan = append(plan, action{kind: "revoke", id: spec.ID, reason: "revoked in spec", spec: spec, entry: entry})
		case spec.Revoked:
			plan = append(plan, action{kind: "unchanged", id: spec.ID, reason: "already revoked", spec: spec, entry: entry})
		case entry.Revoked:
			plan = append(plan, action{kind: "issue", id: spec.ID, reason: "re-registering a revoked client", spec: spec})
		case entry.SpecFingerprint != spec.Fingerprint():
			plan = append(plan, action{kind: "reissue", id: spec.ID, reason: "spec changed", spec: spec, entry: entry})
		default:
			plan = append(plan, action{kind: "unchanged", id: spec.ID, reason: "up to date", spec: spec, entry: entry})
		}
	}

	// Entries with no spec file.
	var orphans []action
	for _, e := range s.Register.Entries {
		if e.ClientID == "" || e.Superseded || e.Revoked || inSpec[e.ClientID] {
			continue
		}
		kind, reason := "unchanged", "spec file removed — rerun with --prune to revoke"
		if applyOpts.prune {
			kind, reason = "revoke", "spec file removed (--prune)"
		}
		orphans = append(orphans, action{kind: kind, id: e.ClientID, reason: reason, entry: e})
	}
	sort.Slice(orphans, func(i, j int) bool { return orphans[i].id < orphans[j].id })
	return append(plan, orphans...)
}

func hasWork(plan []action) bool {
	for _, a := range plan {
		if a.kind != "unchanged" {
			return true
		}
	}
	return false
}

func printPlan(plan []action) {
	fmt.Printf("%-10s  %-28s  %s\n", "ACTION", "CLIENT", "REASON")
	for _, a := range plan {
		fmt.Printf("%-10s  %-28s  %s\n", a.kind, a.id, a.reason)
	}
}

// applyIssue mints a new WRPAC and WRPRC for a spec, superseding and revoking
// any certificate it replaces.
func applyIssue(s *store.Store, ca *wrpac.CA, a action) error {
	spec := a.spec
	validity, err := spec.ValidityDuration()
	if err != nil {
		return err
	}

	kind := wrpac.LegalPerson
	if spec.SubjectKindValue() == "natural" {
		kind = wrpac.NaturalPerson
	}
	level := wrpac.Normalised
	if spec.AssuranceValue() == "qualified" {
		level = wrpac.Qualified
	}

	issued, err := ca.Issue(wrpac.Request{
		PublicKey:    spec.CertificateRequest().PublicKey,
		Kind:         kind,
		Level:        level,
		CommonName:   spec.Name,
		Organization: spec.Organization,
		GivenName:    spec.GivenName,
		Surname:      spec.Surname,
		Country:      spec.Country,
		Identifier:   spec.Identifier,
		SupportURI:   spec.SupportURI,
		Email:        spec.Email,
		Validity:     validity,
	})
	if err != nil {
		return fmt.Errorf("apply: %s: %w", spec.ID, err)
	}

	serial := fmt.Sprintf("%x", issued.Certificate.SerialNumber)
	entry := &store.Entry{
		Serial:          serial,
		ClientID:        spec.ID,
		SpecFingerprint: spec.Fingerprint(),
		Identifier:      spec.Identifier,
		Name:            spec.Name,
		Entitlements:    spec.Entitlements,
		StatusIndex:     s.AllocateStatusIndex(),
		IssuedAt:        issued.Certificate.NotBefore,
		NotAfter:        issued.Certificate.NotAfter,
	}
	s.Register.Entries[serial] = entry

	if err = store.WriteCert(s.IssuedPath(serial), issued.Certificate); err != nil {
		return err
	}

	token, err := mintWRPRCForSpec(s, entry, spec)
	if err != nil {
		return err
	}

	// Deliver next to the spec's own CSR, so a client's material sits with the
	// request that produced it and can be committed alongside it.
	outDir := applyOpts.out
	if outDir == "" {
		outDir = filepath.Join(filepath.Dir(spec.Path()), spec.ID+".issued")
	} else {
		outDir = filepath.Join(outDir, spec.ID)
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("apply: create %s: %w", outDir, err)
	}
	if err := store.WriteCert(filepath.Join(outDir, "wrpac.pem"), issued.Certificate); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outDir, "wrprc.jwt"), []byte(token+"\n"), 0o644); err != nil {
		return fmt.Errorf("apply: write WRPRC: %w", err)
	}

	// Supersede and revoke what this replaces: leaving the old certificate valid
	// would mean a client whose entitlements were narrowed still holds a
	// certificate asserting the old ones.
	if a.entry != nil {
		a.entry.Superseded = true
		revokeEntry(a.entry, nil)
	}
	return nil
}

// mintWRPRCForSpec builds the registration certificate from a spec.
func mintWRPRCForSpec(s *store.Store, e *store.Entry, spec *clientspec.Spec) (string, error) {
	regCert, err := store.ReadCert(s.RegistrarCertPath())
	if err != nil {
		return "", err
	}
	caCert, err := store.ReadCert(s.CACertPath())
	if err != nil {
		return "", err
	}
	resolved, err := s.RegistrarKeyRef().Resolve()
	if err != nil {
		return "", err
	}
	defer func() { _ = resolved.Close() }()

	var provides []wrprc.Credential
	for _, a := range spec.Provides {
		switch {
		case a.VCT != "":
			provides = append(provides, wrprc.Credential{
				Format: "dc+sd-jwt", Meta: map[string]any{"vct_values": []string{a.VCT}},
			})
		case a.DocType != "":
			provides = append(provides, wrprc.Credential{
				Format: "mso_mdoc", Meta: map[string]any{"doctype_value": a.DocType},
			})
		}
	}

	signer := &wrprc.Signer{Chain: []*x509.Certificate{regCert, caCert}, Key: resolved.Signer}
	return signer.Mint(wrprc.Payload{
		Name:                 spec.Name,
		Sub:                  spec.Identifier,
		SubLegalName:         spec.Organization,
		SubGivenName:         spec.GivenName,
		SubFamilyName:        spec.Surname,
		Country:              spec.Country,
		RegistryURI:          s.Register.BaseURL + "/" + registerFile,
		Entitlements:         spec.Entitlements,
		ProvidesAttestations: provides,
		SupportURI:           spec.SupportURI,
		CertificatePolicy:    s.Register.BaseURL + "/certificate-policy",
		Status: &wrprc.Status{StatusList: wrprc.StatusList{
			Idx: e.StatusIndex,
			URI: s.Register.BaseURL + "/" + statusListFile,
		}},
	})
}

// revokeEntry marks an entry revoked. spec may be nil when superseding.
func revokeEntry(e *store.Entry, spec *clientspec.Spec) {
	if e == nil || e.Revoked {
		return
	}
	now := time.Now().UTC()
	e.Revoked = true
	e.RevokedAt = &now
	if spec != nil {
		e.RevocationReason = spec.RevocationReason
	} else {
		// RFC 5280 CRLReason superseded(4).
		e.RevocationReason = 4
	}
}

func init() {
	addDirFlag(applyCmd)
	f := applyCmd.Flags()
	f.StringVar(&applyOpts.from, "from", "clients", "directory of client spec YAML files")
	f.StringVar(&applyOpts.out, "out", "", "directory for issued material (default: beside each spec)")
	f.BoolVar(&applyOpts.dryRun, "dry-run", false, "print the plan and change nothing")
	f.BoolVar(&applyOpts.prune, "prune", false, "revoke clients whose spec file was removed")
	rootCmd.AddCommand(applyCmd)
}
