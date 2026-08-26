package store

import (
	"path/filepath"
	"testing"
)

func TestCreateRefusesToClobberAnExistingDeployment(t *testing.T) {
	dir := t.TempDir()
	if _, err := Create(dir, "https://r.test"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Re-initialising would replace the CA key and silently invalidate every
	// certificate already issued from it.
	if _, err := Create(dir, "https://r.test"); err == nil {
		t.Fatal("expected re-initialisation to be refused")
	}
}

func TestOpenRejectsAnUninitialisedDirectory(t *testing.T) {
	if _, err := Open(t.TempDir()); err == nil {
		t.Fatal("expected opening an uninitialised directory to fail")
	}
}

func TestStatusIndicesAreNeverReused(t *testing.T) {
	s, err := Create(t.TempDir(), "https://r.test")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[int]bool{}
	for i := 0; i < 5; i++ {
		idx := s.AllocateStatusIndex()
		if seen[idx] {
			t.Fatalf("status index %d was allocated twice", idx)
		}
		seen[idx] = true
	}
}

func TestCRLNumberIsMonotonicAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	s, err := Create(dir, "https://r.test")
	if err != nil {
		t.Fatal(err)
	}
	s.NextCRLNumber()
	s.NextCRLNumber()
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}

	// RFC 5280 requires the CRL number to increase. A deployment that restarted
	// and began again at 1 would have its CRLs ignored as stale.
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := reopened.NextCRLNumber(); got != 3 {
		t.Errorf("CRL number after reopen = %d, want 3", got)
	}
}

func TestRegisterSurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	s, err := Create(dir, "https://r.test")
	if err != nil {
		t.Fatal(err)
	}
	s.Register.Entries["abc"] = &Entry{Serial: "abc", Identifier: "LEIXG-1", Name: "P"}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	e, ok := reopened.Register.Entries["abc"]
	if !ok {
		t.Fatal("entry did not survive reopen")
	}
	if e.Identifier != "LEIXG-1" {
		t.Errorf("identifier = %q, want LEIXG-1", e.Identifier)
	}
}

func TestPathsStayInsideTheDeployment(t *testing.T) {
	s := &Store{Dir: "/tmp/dep"}
	if got := s.IssuedPath("ff"); got != filepath.Join("/tmp/dep", "issued", "ff.pem") {
		t.Errorf("IssuedPath = %q", got)
	}
}
