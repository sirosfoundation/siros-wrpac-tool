// Package keyref resolves a deployment's signing keys, which may live in a file
// or on a PKCS#11 token.
//
// A deployment's CA key is the trust anchor relying parties have configured. On
// a file-backed deployment it is a PKCS#8 file with 0600 permissions, which is
// adequate for testing and interop but is the main reason such a deployment is
// not a supervised trust service. A PKCS#11 reference moves the key onto a token
// where it cannot be copied.
package keyref

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"sync"

	"github.com/sirosfoundation/go-cryptoutil/pkcs11pool"
)

// PKCS#11 modules are initialised once per process: a second C_Initialize
// against the same library returns CKR_CRYPTOKI_ALREADY_INITIALIZED. A
// deployment resolves at least two keys — the CA's and the registrar's — so
// pools are shared per module and reference counted rather than opened per key.
var (
	poolMu sync.Mutex
	pools  = map[string]*sharedPool{}
)

type sharedPool struct {
	pool *pkcs11pool.Pool
	refs int
}

// acquirePool returns a pool for the token, opening one only if this is the
// first reference to that module.
func acquirePool(key string, cfg pkcs11pool.Config) (*pkcs11pool.Pool, error) {
	poolMu.Lock()
	defer poolMu.Unlock()

	if sp, ok := pools[key]; ok {
		sp.refs++
		return sp.pool, nil
	}
	pool, err := pkcs11pool.New(cfg)
	if err != nil {
		return nil, err
	}
	pools[key] = &sharedPool{pool: pool, refs: 1}
	return pool, nil
}

// releasePool drops a reference and finalises the module when the last one goes.
func releasePool(key string) error {
	poolMu.Lock()
	defer poolMu.Unlock()

	sp, ok := pools[key]
	if !ok {
		return nil
	}
	sp.refs--
	if sp.refs > 0 {
		return nil
	}
	delete(pools, key)
	return sp.pool.Close()
}

// PKCS11 identifies a key on a token.
//
// The PIN is deliberately absent: it is supplied at run time from the
// environment, never written into the deployment's register. A register file
// gets copied, committed and shared; a PIN in it would follow.
type PKCS11 struct {
	// Module is the path to the PKCS#11 shared library.
	Module string `json:"module"`
	// TokenLabel selects the slot by token label. Takes precedence over SlotID.
	TokenLabel string `json:"token_label,omitempty"`
	// SlotID selects the slot by number when TokenLabel is empty.
	SlotID uint `json:"slot_id,omitempty"`
	// KeyLabel is the CKA_LABEL of the key to sign with.
	KeyLabel string `json:"key_label"`
	// PINEnv names the environment variable holding the user PIN.
	PINEnv string `json:"pin_env,omitempty"`
}

// Ref points at a signing key. Exactly one form is set.
type Ref struct {
	// File is a path to a PEM PKCS#8 private key.
	File string `json:"file,omitempty"`
	// PKCS11 describes a key on a token.
	PKCS11 *PKCS11 `json:"pkcs11,omitempty"`
}

// IsPKCS11 reports whether the key lives on a token.
func (r Ref) IsPKCS11() bool { return r.PKCS11 != nil }

// Describe returns a short human-readable form, safe to log — it never includes
// a PIN.
func (r Ref) Describe() string {
	if r.PKCS11 != nil {
		where := r.PKCS11.TokenLabel
		if where == "" {
			where = fmt.Sprintf("slot %d", r.PKCS11.SlotID)
		}
		return fmt.Sprintf("pkcs11 %s on %s via %s", r.PKCS11.KeyLabel, where, r.PKCS11.Module)
	}
	return "file " + r.File
}

// Resolved is an open signer plus the cleanup its backing resources need.
type Resolved struct {
	Signer crypto.Signer
	// Close releases the PKCS#11 session pool. It is a no-op for file keys, so
	// callers can always defer it.
	Close func() error
}

// Resolve opens the key and returns a crypto.Signer for it.
func (r Ref) Resolve() (*Resolved, error) {
	if r.PKCS11 != nil {
		return r.resolvePKCS11()
	}
	if r.File == "" {
		return nil, fmt.Errorf("keyref: no key reference configured")
	}
	key, err := readPEMKey(r.File)
	if err != nil {
		return nil, err
	}
	return &Resolved{Signer: key, Close: func() error { return nil }}, nil
}

func (r Ref) resolvePKCS11() (*Resolved, error) {
	p := r.PKCS11
	if p.Module == "" {
		return nil, fmt.Errorf("keyref: pkcs11 module path is required")
	}
	if p.KeyLabel == "" {
		return nil, fmt.Errorf("keyref: pkcs11 key label is required")
	}

	pinEnv := p.PINEnv
	if pinEnv == "" {
		pinEnv = "SIROS_WRPAC_PKCS11_PIN"
	}
	pin, ok := os.LookupEnv(pinEnv)
	if !ok {
		return nil, fmt.Errorf("keyref: PKCS#11 PIN not found; set %s", pinEnv)
	}

	poolKey := fmt.Sprintf("%s|%s|%d", p.Module, p.TokenLabel, p.SlotID)
	pool, err := acquirePool(poolKey, pkcs11pool.Config{
		ModulePath: p.Module,
		TokenLabel: p.TokenLabel,
		SlotID:     p.SlotID,
		PIN:        pin,
	})
	if err != nil {
		return nil, fmt.Errorf("keyref: open pkcs11 token: %w", err)
	}

	signer, err := pkcs11pool.NewSigner(pool, pkcs11pool.KeyByLabel(p.KeyLabel))
	if err != nil {
		// Release here: a failed lookup would otherwise hold a reference
		// forever and keep the module initialised for the process lifetime.
		_ = releasePool(poolKey)
		return nil, fmt.Errorf("keyref: find key %q: %w", p.KeyLabel, err)
	}

	var once sync.Once
	return &Resolved{Signer: signer, Close: func() error {
		// Closing twice must not drop two references, or an unrelated key's
		// pool would be finalised out from under it.
		var err error
		once.Do(func() { err = releasePool(poolKey) })
		return err
	}}, nil
}

func readPEMKey(path string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("keyref: read %s: %w", path, err)
	}
	blk, _ := pem.Decode(raw)
	if blk == nil {
		return nil, fmt.Errorf("keyref: %s is not PEM", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("keyref: parse %s: %w", path, err)
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("keyref: %s is not an ECDSA key, got %T", path, k)
	}
	return key, nil
}
