package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sirosfoundation/siros-wrpac-tool/pkg/store"
)

const pidSpec = `name: Acme PID Provider
organization: Acme AB
identifier: LEIXG-ACME00T8BM49AURSDO11
country: SE
support_uri: https://acme.test/support
csr: acme.csr
entitlements:
  - https://uri.etsi.org/19475/Entitlement/PID_Provider
provides:
  - vct: urn:eudi:pid:1
`

// newSpecRepo writes a client spec directory and points apply at it.
func newSpecRepo(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	writeCSR(t, dir, "acme")
	if err := os.WriteFile(filepath.Join(dir, "acme.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	applyOpts.from = dir
	applyOpts.out = filepath.Join(t.TempDir(), "issued")
	applyOpts.dryRun = false
	applyOpts.prune = false
	return dir
}

func TestApplyIssuesFromASpec(t *testing.T) {
	dep := newDeployment(t)
	newSpecRepo(t, pidSpec)

	if err := runApply(nil, nil); err != nil {
		t.Fatalf("apply: %v", err)
	}

	s, err := store.Open(dep)
	if err != nil {
		t.Fatal(err)
	}
	entry := s.ActiveByClient("acme")
	if entry == nil {
		t.Fatal("no active entry for the client")
	}
	if entry.SpecFingerprint == "" {
		t.Error("entry has no spec fingerprint, so drift can never be detected")
	}

	// The CSR path must not produce a private key: the client holds it.
	out := filepath.Join(applyOpts.out, "acme")
	if _, err := os.Stat(filepath.Join(out, "wrpac.pem")); err != nil {
		t.Errorf("certificate missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(out, "wrpac.key")); err == nil {
		t.Error("a private key was written — the CSR path must never produce one")
	}
}

func TestApplyIsIdempotent(t *testing.T) {
	dep := newDeployment(t)
	newSpecRepo(t, pidSpec)

	if err := runApply(nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := runApply(nil, nil); err != nil {
		t.Fatal(err)
	}

	s, err := store.Open(dep)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Register.Entries) != 1 {
		t.Errorf("register has %d entries after two runs, want 1", len(s.Register.Entries))
	}
}

func TestApplyDryRunChangesNothing(t *testing.T) {
	dep := newDeployment(t)
	newSpecRepo(t, pidSpec)
	applyOpts.dryRun = true

	if err := runApply(nil, nil); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(dep)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Register.Entries) != 0 {
		t.Errorf("dry run issued %d certificates", len(s.Register.Entries))
	}
}

// A changed spec re-issues and revokes what it replaces. Leaving the old
// certificate valid would let a client whose entitlements were narrowed keep
// using one that asserts the old set.
func TestApplyReissuesAndRevokesTheOldCertificate(t *testing.T) {
	dep := newDeployment(t)
	dir := newSpecRepo(t, pidSpec)

	if err := runApply(nil, nil); err != nil {
		t.Fatal(err)
	}
	narrowed := pidSpec[:len(pidSpec)-len("provides:\n  - vct: urn:eudi:pid:1\n")]
	if err := os.WriteFile(filepath.Join(dir, "acme.yaml"), []byte(narrowed), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := runApply(nil, nil); err != nil {
		t.Fatal(err)
	}

	s, err := store.Open(dep)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Register.Entries) != 2 {
		t.Fatalf("want two entries after re-issuance, got %d", len(s.Register.Entries))
	}
	var superseded, active int
	for _, e := range s.Register.Entries {
		if e.Superseded {
			superseded++
			if !e.Revoked {
				t.Error("the superseded certificate was not revoked")
			}
			if e.RevocationReason != 4 {
				t.Errorf("revocation reason = %d, want superseded(4)", e.RevocationReason)
			}
		} else {
			active++
		}
	}
	if superseded != 1 || active != 1 {
		t.Errorf("superseded=%d active=%d, want 1 and 1", superseded, active)
	}
}

func TestApplyRevokesWhenSpecSaysSo(t *testing.T) {
	dep := newDeployment(t)
	dir := newSpecRepo(t, pidSpec)
	if err := runApply(nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "acme.yaml"), []byte(pidSpec+"revoked: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := runApply(nil, nil); err != nil {
		t.Fatal(err)
	}

	s, err := store.Open(dep)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range s.Register.Entries {
		if !e.Revoked {
			t.Error("the client was not revoked")
		}
	}
}

// Deleting a spec must not revoke without --prune: revocation is close to
// irreversible and an accidental deletion should not take a party out of service.
func TestApplyDeletionNeedsPrune(t *testing.T) {
	dep := newDeployment(t)
	dir := newSpecRepo(t, pidSpec)
	if err := runApply(nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "acme.yaml")); err != nil {
		t.Fatal(err)
	}

	if err := runApply(nil, nil); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(dep)
	if err != nil {
		t.Fatal(err)
	}
	if s.ActiveByClient("acme") == nil {
		t.Fatal("the client vanished without --prune")
	}
	if s.ActiveByClient("acme").Revoked {
		t.Fatal("deleting a spec revoked the client without --prune")
	}

	applyOpts.prune = true
	if err := runApply(nil, nil); err != nil {
		t.Fatal(err)
	}
	s, err = store.Open(dep)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range s.Register.Entries {
		if e.ClientID == "acme" {
			found = true
			if !e.Revoked {
				t.Error("--prune did not revoke the removed client")
			}
		}
	}
	if !found {
		t.Error("entry disappeared entirely")
	}
}

func TestApplyRejectsABadSpecDirectory(t *testing.T) {
	newDeployment(t)
	applyOpts.from = filepath.Join(t.TempDir(), "nope")
	applyOpts.dryRun = false
	if err := runApply(nil, nil); err == nil {
		t.Fatal("expected a missing spec directory to fail")
	}
}

// A spec already marked revoked and never issued must not put a dead
// certificate into circulation.
func TestApplySkipsRevokedAndNeverIssued(t *testing.T) {
	dep := newDeployment(t)
	newSpecRepo(t, pidSpec+"revoked: true\n")

	if err := runApply(nil, nil); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(dep)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Register.Entries) != 0 {
		t.Errorf("issued %d certificates for a revoked spec", len(s.Register.Entries))
	}
}
