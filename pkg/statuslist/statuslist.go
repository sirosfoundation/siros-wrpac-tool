// Package statuslist builds IETF Token Status List documents.
//
// The registration certificates this tool mints carry a status.status_list
// reference. Serving the list it points at is what makes revoking a WRPRC
// observable — without it the reference is a promise nothing keeps.
package statuslist

import (
	"bytes"
	"compress/zlib"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/sirosfoundation/siros-wrpac-tool/pkg/jws"
)

// MediaType is the status list JWT media type.
const MediaType = "statuslist+jwt"

// List is a one-bit-per-entry status list: 0 valid, 1 revoked.
type List struct {
	bits []byte
	size int
}

// New returns a list sized for n entries, all valid.
func New(n int) *List {
	if n < 8 {
		n = 8
	}
	return &List{bits: make([]byte, (n+7)/8), size: n}
}

// Revoke marks index i revoked.
func (l *List) Revoke(i int) error {
	if i < 0 || i >= l.size {
		return fmt.Errorf("statuslist: index %d out of range (size %d)", i, l.size)
	}
	l.bits[i/8] |= 1 << (i % 8)
	return nil
}

// IsRevoked reports the bit at index i.
func (l *List) IsRevoked(i int) bool {
	if i < 0 || i >= l.size {
		return false
	}
	return l.bits[i/8]&(1<<(i%8)) != 0
}

// encode returns the zlib-compressed, base64url-encoded bit string.
func (l *List) encode() (string, error) {
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write(l.bits); err != nil {
		return "", fmt.Errorf("statuslist: compress: %w", err)
	}
	if err := zw.Close(); err != nil {
		return "", fmt.Errorf("statuslist: finish compression: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf.Bytes()), nil
}

type payload struct {
	Issuer     string     `json:"iss"`
	Subject    string     `json:"sub"`
	IssuedAt   int64      `json:"iat"`
	Expires    int64      `json:"exp,omitempty"`
	TTL        int        `json:"ttl,omitempty"`
	StatusList statusList `json:"status_list"`
}

type statusList struct {
	Bits int    `json:"bits"`
	List string `json:"lst"`
}

// Sign produces a signed status list token published at uri.
//
// ttl tells a consumer how long it may cache the list; validity sets exp, the
// point after which the token must not be accepted at all. The two are distinct
// on purpose. A deployment that republishes on a schedule needs exp to outlast
// the gap between runs, or the list is expired most of the time, while the cache
// hint stays short: a stale status list is how a revoked certificate keeps being
// accepted. ttl is capped at validity so the two never contradict each other.
func (l *List) Sign(issuer, uri string, key crypto.Signer, chain []*x509.Certificate, ttl, validity time.Duration) (string, error) {
	encoded, err := l.encode()
	if err != nil {
		return "", err
	}
	if validity <= 0 {
		return "", fmt.Errorf("statuslist: validity must be positive, got %s", validity)
	}
	if ttl <= 0 || ttl > validity {
		ttl = validity
	}
	now := time.Now().UTC()
	return jws.Sign(MediaType, payload{
		Issuer:     issuer,
		Subject:    uri,
		IssuedAt:   now.Unix(),
		Expires:    now.Add(validity).Unix(),
		TTL:        int(ttl.Seconds()),
		StatusList: statusList{Bits: 1, List: encoded},
	}, key, chain)
}
