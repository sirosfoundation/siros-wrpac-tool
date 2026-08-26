// Package clientspec reads the declarative description of the wallet-relying
// parties a deployment serves.
//
// A directory of per-client YAML files, kept in git, is the source of truth for
// who is registered and what they are entitled to. The deployment's register is
// derived from it. That split is deliberate: a management UI only ever writes
// YAML and commits it, and never touches the store, so the two can be built and
// replaced independently.
//
// Each client supplies a certificate signing request. The deployment certifies
// the public key in it and never holds the private half, which is what a
// registrar actually does — and means the git repository plus the deployment
// together still contain no client secrets.
package clientspec

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Attestation declares one credential type a provider is registered to issue.
// Exactly one of VCT or DocType is set; the format follows from which.
type Attestation struct {
	VCT     string `yaml:"vct,omitempty" json:"vct,omitempty"`
	DocType string `yaml:"doctype,omitempty" json:"doctype,omitempty"`
}

// Spec is one wallet-relying party, as described by its YAML file.
type Spec struct {
	// ID is the stable key for this client. It defaults to the filename stem and
	// must never change: it is what ties a YAML file to its register entry
	// across re-issuance.
	ID string `yaml:"id,omitempty" json:"id"`

	Name         string `yaml:"name" json:"name"`
	Organization string `yaml:"organization,omitempty" json:"organization,omitempty"`
	GivenName    string `yaml:"given_name,omitempty" json:"given_name,omitempty"`
	Surname      string `yaml:"surname,omitempty" json:"surname,omitempty"`

	// Identifier is the EU-wide unique WRP identifier in EN 319 412-1 semantic
	// form, e.g. "LEIXG-529900T8BM49AURSDO55".
	Identifier string `yaml:"identifier" json:"identifier"`
	Country    string `yaml:"country" json:"country"`

	SupportURI string `yaml:"support_uri,omitempty" json:"support_uri,omitempty"`
	Email      string `yaml:"email,omitempty" json:"email,omitempty"`

	// SubjectKind is "legal" (default) or "natural".
	SubjectKind string `yaml:"subject_kind,omitempty" json:"subject_kind,omitempty"`
	// Assurance is "normalised" (default) or "qualified".
	Assurance string `yaml:"assurance,omitempty" json:"assurance,omitempty"`

	// CSR is the path to the client's certificate signing request, relative to
	// the YAML file. Required: the deployment certifies a key it does not hold.
	CSR string `yaml:"csr" json:"csr"`

	Entitlements []string      `yaml:"entitlements" json:"entitlements"`
	Provides     []Attestation `yaml:"provides,omitempty" json:"provides,omitempty"`

	// Validity is a Go duration, e.g. "8760h". Defaults to one year.
	Validity string `yaml:"validity,omitempty" json:"validity,omitempty"`

	// Revoked suspends or cancels the registration. Setting it is the reversible
	// way to take a client out of service; deleting the file is not, which is why
	// deletion requires an explicit --prune.
	Revoked          bool `yaml:"revoked,omitempty" json:"revoked,omitempty"`
	RevocationReason int  `yaml:"revocation_reason,omitempty" json:"revocation_reason,omitempty"`

	// path and csr are resolved at load time and excluded from the fingerprint
	// input, since where a file sits on disk is not part of what was registered.
	path string
	csr  *x509.CertificateRequest
}

// Path returns the file this spec was read from.
func (s *Spec) Path() string { return s.path }

// CertificateRequest returns the parsed, signature-checked CSR.
func (s *Spec) CertificateRequest() *x509.CertificateRequest { return s.csr }

// ValidityDuration returns the requested certificate lifetime.
func (s *Spec) ValidityDuration() (time.Duration, error) {
	if s.Validity == "" {
		return 365 * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s.Validity)
	if err != nil {
		return 0, fmt.Errorf("clientspec: %s: invalid validity %q: %w", s.ID, s.Validity, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("clientspec: %s: validity must be positive", s.ID)
	}
	return d, nil
}

// Fingerprint is a stable hash of everything that affects what gets issued.
//
// Reconciliation re-issues when it changes, so it must cover the CSR's public
// key as well as the subject and entitlement fields — a client rotating its key
// must get a new certificate. It deliberately excludes Revoked, which is handled
// as its own transition rather than as a reason to re-issue.
func (s *Spec) Fingerprint() string {
	type material struct {
		Name         string        `json:"name"`
		Organization string        `json:"organization"`
		GivenName    string        `json:"given_name"`
		Surname      string        `json:"surname"`
		Identifier   string        `json:"identifier"`
		Country      string        `json:"country"`
		SupportURI   string        `json:"support_uri"`
		Email        string        `json:"email"`
		SubjectKind  string        `json:"subject_kind"`
		Assurance    string        `json:"assurance"`
		Entitlements []string      `json:"entitlements"`
		Provides     []Attestation `json:"provides"`
		Validity     string        `json:"validity"`
		PublicKey    string        `json:"public_key"`
	}

	ents := append([]string(nil), s.Entitlements...)
	sort.Strings(ents)

	m := material{
		Name: s.Name, Organization: s.Organization,
		GivenName: s.GivenName, Surname: s.Surname,
		Identifier: s.Identifier, Country: s.Country,
		SupportURI: s.SupportURI, Email: s.Email,
		SubjectKind: s.subjectKind(), Assurance: s.assurance(),
		Entitlements: ents, Provides: s.Provides,
		Validity: s.Validity,
	}
	if s.csr != nil {
		if der, err := x509.MarshalPKIXPublicKey(s.csr.PublicKey); err == nil {
			sum := sha256.Sum256(der)
			m.PublicKey = hex.EncodeToString(sum[:])
		}
	}

	raw, err := json.Marshal(m)
	if err != nil {
		// The struct is plain data; marshalling it cannot fail in practice, and
		// a fingerprint that silently degrades would suppress re-issuance.
		panic(fmt.Sprintf("clientspec: fingerprint marshal: %v", err))
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func (s *Spec) subjectKind() string {
	if s.SubjectKind == "" {
		return "legal"
	}
	return s.SubjectKind
}

func (s *Spec) assurance() string {
	if s.Assurance == "" {
		return "normalised"
	}
	return s.Assurance
}

// SubjectKindValue and AssuranceValue expose the normalised values.
func (s *Spec) SubjectKindValue() string { return s.subjectKind() }
func (s *Spec) AssuranceValue() string   { return s.assurance() }

// Validate checks a spec is internally consistent and issuable.
func (s *Spec) Validate() error {
	if s.ID == "" {
		return fmt.Errorf("clientspec: id is required")
	}
	if s.Name == "" {
		return fmt.Errorf("clientspec: %s: name is required", s.ID)
	}
	if s.Identifier == "" {
		return fmt.Errorf("clientspec: %s: identifier is required", s.ID)
	}
	if s.SupportURI == "" && s.Email == "" {
		return fmt.Errorf("clientspec: %s: support_uri or email is required (subjectAltName must carry a contact)", s.ID)
	}
	if len(s.Entitlements) == 0 {
		return fmt.Errorf("clientspec: %s: at least one entitlement is required", s.ID)
	}
	switch s.subjectKind() {
	case "legal":
		if s.Organization == "" {
			return fmt.Errorf("clientspec: %s: organization is required for a legal person", s.ID)
		}
	case "natural":
	default:
		return fmt.Errorf("clientspec: %s: subject_kind must be legal or natural, got %q", s.ID, s.SubjectKind)
	}
	switch s.assurance() {
	case "normalised", "qualified":
	default:
		return fmt.Errorf("clientspec: %s: assurance must be normalised or qualified, got %q", s.ID, s.Assurance)
	}
	for _, a := range s.Provides {
		if (a.VCT == "") == (a.DocType == "") {
			return fmt.Errorf("clientspec: %s: each provides entry needs exactly one of vct or doctype", s.ID)
		}
	}
	if _, err := s.ValidityDuration(); err != nil {
		return err
	}
	if s.CSR == "" {
		return fmt.Errorf("clientspec: %s: csr is required", s.ID)
	}
	return nil
}

// Load reads every *.yaml and *.yml file in dir as a client spec.
func Load(dir string) ([]*Spec, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("clientspec: read %s: %w", dir, err)
	}

	var specs []*Spec
	seen := map[string]string{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		spec, err := LoadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		// Two files claiming the same id would reconcile against each other on
		// every run, each undoing the other.
		if prev, dup := seen[spec.ID]; dup {
			return nil, fmt.Errorf("clientspec: id %q declared by both %s and %s", spec.ID, prev, spec.path)
		}
		seen[spec.ID] = spec.path
		specs = append(specs, spec)
	}
	sort.Slice(specs, func(i, j int) bool { return specs[i].ID < specs[j].ID })
	return specs, nil
}

// LoadFile reads a single client spec and its CSR.
func LoadFile(path string) (*Spec, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("clientspec: read %s: %w", path, err)
	}

	spec := &Spec{path: path}
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true) // a misspelled key must fail, not be silently ignored
	if err = dec.Decode(spec); err != nil {
		return nil, fmt.Errorf("clientspec: parse %s: %w", path, err)
	}
	if spec.ID == "" {
		base := filepath.Base(path)
		spec.ID = strings.TrimSuffix(base, filepath.Ext(base))
	}
	if err = spec.Validate(); err != nil {
		return nil, err
	}

	csrPath := spec.CSR
	if !filepath.IsAbs(csrPath) {
		csrPath = filepath.Join(filepath.Dir(path), csrPath)
	}
	csr, err := readCSR(csrPath)
	if err != nil {
		return nil, fmt.Errorf("clientspec: %s: %w", spec.ID, err)
	}
	spec.csr = csr
	return spec, nil
}

// readCSR parses a PEM certificate request and checks its self-signature.
//
// That check is the proof of possession: it shows the requester holds the
// private key for the public key being certified. Skipping it would let anyone
// have a certificate issued over someone else's key.
func readCSR(path string) (*x509.CertificateRequest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read csr %s: %w", path, err)
	}
	blk, _ := pem.Decode(raw)
	if blk == nil {
		return nil, fmt.Errorf("csr %s is not PEM", path)
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse csr %s: %w", path, err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("csr %s fails its own signature check (proof of possession): %w", path, err)
	}
	return csr, nil
}
