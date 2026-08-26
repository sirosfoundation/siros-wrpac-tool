package wrpac

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"
)

// CA is an Access Certificate Authority: it signs WRPACs and publishes a CRL
// so that revocation of an access certificate is observable.
type CA struct {
	Certificate *x509.Certificate
	Key         crypto.Signer

	// CRLDistributionPoint is embedded in every certificate this CA issues.
	CRLDistributionPoint string
}

// CAOptions configures NewCA.
type CAOptions struct {
	CommonName           string
	Organization         string
	Country              string
	Validity             time.Duration
	CRLDistributionPoint string
}

// serialNumber returns a positive random 128-bit serial.
//
// Serials must be positive: a leading high bit encodes as a negative INTEGER,
// which some relying parties reject outright.
func serialNumber() (*big.Int, error) {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, fmt.Errorf("serial: %w", err)
	}
	return n.Add(n, big.NewInt(1)), nil
}

// NewCA creates a self-signed Access CA.
func NewCA(opts CAOptions) (*CA, error) {
	if opts.CommonName == "" {
		return nil, fmt.Errorf("wrpac: CA common name is required")
	}
	if opts.Validity == 0 {
		opts.Validity = 10 * 365 * 24 * time.Hour
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("wrpac: generate CA key: %w", err)
	}
	serial, err := serialNumber()
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   opts.CommonName,
			Organization: nonEmpty(opts.Organization),
			Country:      nonEmpty(opts.Country),
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(opts.Validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, fmt.Errorf("wrpac: create CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("wrpac: parse CA certificate: %w", err)
	}

	return &CA{Certificate: cert, Key: key, CRLDistributionPoint: opts.CRLDistributionPoint}, nil
}

// CreateCRL issues a CRL listing the supplied revoked certificates.
//
// An empty list is meaningful and must still be published: "nothing is revoked"
// is a different statement from "no CRL available", and a consumer that cannot
// fetch a CRL should not treat that as evidence of revocation.
func (c *CA) CreateCRL(revoked []x509.RevocationListEntry, thisUpdate time.Time, validity time.Duration) ([]byte, error) {
	serial, err := serialNumber()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.RevocationList{
		Number:                    serial,
		ThisUpdate:                thisUpdate,
		NextUpdate:                thisUpdate.Add(validity),
		RevokedCertificateEntries: revoked,
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, c.Certificate, c.Key)
	if err != nil {
		return nil, fmt.Errorf("wrpac: create CRL: %w", err)
	}
	return der, nil
}

func nonEmpty(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}
