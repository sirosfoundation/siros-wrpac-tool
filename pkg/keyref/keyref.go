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

	"github.com/sirosfoundation/go-cryptoutil/pkcs11pool"
)

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

	pool, err := pkcs11pool.New(pkcs11pool.Config{
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
		// Closing here matters: a failed lookup would otherwise leak the
		// sessions the pool just opened against the token.
		_ = pool.Close()
		return nil, fmt.Errorf("keyref: find key %q: %w", p.KeyLabel, err)
	}
	return &Resolved{Signer: signer, Close: pool.Close}, nil
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
