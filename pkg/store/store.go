// Package store holds the on-disk state of a running deployment: the Access CA,
// the registration certificate provider, and the register of what has been
// issued and revoked.
//
// A sandbox can regenerate everything on each run. A deployment cannot: its CA
// key is the trust anchor relying parties have already configured, and its CRL
// numbers and status-list indices have to move forward monotonically. Everything
// that must survive a restart lives here.
package store

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/sirosfoundation/siros-wrpac-tool/pkg/keyref"
)

// Layout of a deployment directory.
const (
	dirPublic  = "public"
	dirIssued  = "issued"
	fileDB     = "register.json"
	fileCACert = "ca.pem"
	fileCAKey  = "ca.key"
	fileRegCrt = "registrar.pem"
	fileRegKey = "registrar.key"
)

// Entry is one issued wallet-relying party, as recorded in the register.
type Entry struct {
	// Serial is the certificate serial in hex, and names the file under issued/.
	Serial string `json:"serial"`
	// ClientID ties this entry to a spec file when the deployment is driven
	// declaratively. Empty for entries created by `issue` directly.
	ClientID string `json:"client_id,omitempty"`
	// SpecFingerprint is the spec hash this entry was issued from. Reconciliation
	// compares against it to decide whether re-issuance is needed.
	SpecFingerprint string `json:"spec_fingerprint,omitempty"`
	// Superseded marks an entry replaced by a later issuance for the same client.
	Superseded bool `json:"superseded,omitempty"`
	// Identifier is the EU-wide unique WRP identifier.
	Identifier string `json:"identifier"`
	Name       string `json:"name"`
	// Entitlements are the WRPRC entitlement URIs granted at registration.
	Entitlements []string `json:"entitlements,omitempty"`
	// StatusIndex is this WRP's slot in the registration-certificate status list.
	// Allocated once and never reused: reusing a slot would silently transfer a
	// previous holder's revocation to a new certificate.
	StatusIndex int       `json:"status_index"`
	IssuedAt    time.Time `json:"issued_at"`
	NotAfter    time.Time `json:"not_after"`

	// Revoked is set when the WRP's registration is suspended or cancelled.
	Revoked   bool       `json:"revoked,omitempty"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	// RevocationReason is an RFC 5280 CRLReason value.
	RevocationReason int `json:"revocation_reason,omitempty"`
}

// Register is the persisted state of the deployment.
type Register struct {
	// CRLNumber is monotonic. RFC 5280 requires it to increase, and a relying
	// party that caches CRLs will ignore one that appears to go backwards.
	CRLNumber int `json:"crl_number"`
	// NextStatusIndex is the next unallocated status list slot.
	NextStatusIndex int `json:"next_status_index"`
	// BaseURL is where this deployment publishes its CRL and status list.
	BaseURL string `json:"base_url"`
	// CRLValidity and StatusListValidity are Go durations ("168h") bounding
	// how long a published CRL and status list token stay acceptable. They are
	// deployment settings rather than publish-time flags because every caller
	// of publish — init, issue, revoke, apply — must agree, and because the
	// value encodes an operational promise: republish at least this often.
	// Empty means DefaultRevocationValidity.
	CRLValidity        string `json:"crl_validity,omitempty"`
	StatusListValidity string `json:"status_list_validity,omitempty"`
	// Entries is keyed by certificate serial.
	Entries map[string]*Entry `json:"entries"`

	// CAKey and RegistrarKey say where the deployment's two signing keys live.
	// Empty means the historical layout: ca.key and registrar.key beside the
	// register. Neither ever carries a PIN — see keyref.PKCS11.
	CAKey        keyref.Ref `json:"ca_key,omitempty"`
	RegistrarKey keyref.Ref `json:"registrar_key,omitempty"`
}

// DefaultRevocationValidity is how long a CRL or status list stays acceptable
// when the register does not say. A week matches common CRL practice and gives
// a scheduled republish room to fail once and be retried.
const DefaultRevocationValidity = 7 * 24 * time.Hour

// CRLValidityDuration returns the configured CRL validity, or the default.
func (s *Store) CRLValidityDuration() (time.Duration, error) {
	return parseValidity("crl_validity", s.Register.CRLValidity)
}

// StatusListValidityDuration returns the configured status list token
// validity, or the default.
func (s *Store) StatusListValidityDuration() (time.Duration, error) {
	return parseValidity("status_list_validity", s.Register.StatusListValidity)
}

func parseValidity(field, raw string) (time.Duration, error) {
	if raw == "" {
		return DefaultRevocationValidity, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("store: register %s %q: %w", field, raw, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("store: register %s must be positive, got %q", field, raw)
	}
	return d, nil
}

// CAKeyRef returns the CA key reference, defaulting to the on-disk layout.
func (s *Store) CAKeyRef() keyref.Ref {
	if s.Register.CAKey.File == "" && s.Register.CAKey.PKCS11 == nil {
		return keyref.Ref{File: s.CAKeyPath()}
	}
	return s.Register.CAKey
}

// RegistrarKeyRef returns the registrar key reference, defaulting to the
// on-disk layout.
func (s *Store) RegistrarKeyRef() keyref.Ref {
	if s.Register.RegistrarKey.File == "" && s.Register.RegistrarKey.PKCS11 == nil {
		return keyref.Ref{File: s.RegistrarKeyPath()}
	}
	return s.Register.RegistrarKey
}

// Store is an open deployment directory.
type Store struct {
	Dir      string
	Register *Register
}

// Open loads an existing deployment directory.
func Open(dir string) (*Store, error) {
	raw, err := os.ReadFile(filepath.Join(dir, fileDB))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("store: %s is not an initialised deployment (run `siros-wrpac-tool init -d %s` first)", dir, dir)
		}
		return nil, fmt.Errorf("store: read register: %w", err)
	}
	reg := &Register{}
	if err := json.Unmarshal(raw, reg); err != nil {
		return nil, fmt.Errorf("store: parse register: %w", err)
	}
	if reg.Entries == nil {
		reg.Entries = map[string]*Entry{}
	}
	return &Store{Dir: dir, Register: reg}, nil
}

// Create initialises a new deployment directory. It refuses to overwrite an
// existing one: clobbering a CA key silently invalidates every certificate that
// chains to it.
func Create(dir, baseURL string) (*Store, error) {
	if _, err := os.Stat(filepath.Join(dir, fileDB)); err == nil {
		return nil, fmt.Errorf("store: %s is already initialised; refusing to overwrite its CA", dir)
	}
	for _, d := range []string{dir, filepath.Join(dir, dirPublic), filepath.Join(dir, dirIssued)} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, fmt.Errorf("store: create %s: %w", d, err)
		}
	}
	s := &Store{Dir: dir, Register: &Register{BaseURL: baseURL, Entries: map[string]*Entry{}}}
	return s, s.Save()
}

// Save writes the register back atomically, so an interrupted write cannot leave
// a deployment with a truncated register and an unusable CA.
func (s *Store) Save() error {
	raw, err := json.MarshalIndent(s.Register, "", "  ")
	if err != nil {
		return fmt.Errorf("store: marshal register: %w", err)
	}
	final := filepath.Join(s.Dir, fileDB)
	tmp := final + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o644); err != nil {
		return fmt.Errorf("store: write register: %w", err)
	}
	if err := os.Rename(tmp, final); err != nil {
		return fmt.Errorf("store: replace register: %w", err)
	}
	return nil
}

// ActiveByClient returns the current, non-superseded entry for a client id.
func (s *Store) ActiveByClient(clientID string) *Entry {
	for _, e := range s.Register.Entries {
		if e.ClientID == clientID && !e.Superseded {
			return e
		}
	}
	return nil
}

// AllocateStatusIndex reserves the next status list slot.
func (s *Store) AllocateStatusIndex() int {
	i := s.Register.NextStatusIndex
	s.Register.NextStatusIndex++
	return i
}

// NextCRLNumber increments and returns the CRL number.
func (s *Store) NextCRLNumber() int {
	s.Register.CRLNumber++
	return s.Register.CRLNumber
}

// Paths within the deployment directory.
func (s *Store) CACertPath() string        { return filepath.Join(s.Dir, fileCACert) }
func (s *Store) CAKeyPath() string         { return filepath.Join(s.Dir, fileCAKey) }
func (s *Store) RegistrarCertPath() string { return filepath.Join(s.Dir, fileRegCrt) }
func (s *Store) RegistrarKeyPath() string  { return filepath.Join(s.Dir, fileRegKey) }
func (s *Store) PublicDir() string         { return filepath.Join(s.Dir, dirPublic) }
func (s *Store) IssuedPath(serial string) string {
	return filepath.Join(s.Dir, dirIssued, serial+".pem")
}

// WriteCert writes a PEM certificate.
func WriteCert(path string, cert *x509.Certificate) error {
	b := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return fmt.Errorf("store: write %s: %w", path, err)
	}
	return nil
}

// WriteKey writes a PKCS#8 private key with owner-only permissions.
func WriteKey(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("store: marshal key: %w", err)
	}
	b := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return fmt.Errorf("store: write %s: %w", path, err)
	}
	return nil
}

// ReadCert loads a PEM certificate.
func ReadCert(path string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("store: read %s: %w", path, err)
	}
	blk, _ := pem.Decode(raw)
	if blk == nil {
		return nil, fmt.Errorf("store: %s is not PEM", path)
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("store: parse %s: %w", path, err)
	}
	return cert, nil
}

// ReadKey loads a PKCS#8 ECDSA private key.
func ReadKey(path string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("store: read %s: %w", path, err)
	}
	blk, _ := pem.Decode(raw)
	if blk == nil {
		return nil, fmt.Errorf("store: %s is not PEM", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("store: parse %s: %w", path, err)
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("store: %s is not an ECDSA key, got %T", path, k)
	}
	return key, nil
}
