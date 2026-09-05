package statuslist

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"
)

func TestRevokeSetsOnlyTheNamedIndex(t *testing.T) {
	l := New(24)
	if err := l.Revoke(5); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	for i := 0; i < 24; i++ {
		want := i == 5
		if got := l.IsRevoked(i); got != want {
			t.Errorf("IsRevoked(%d) = %v, want %v", i, got, want)
		}
	}
}

func TestRevokeRejectsOutOfRange(t *testing.T) {
	l := New(8)
	if err := l.Revoke(8); err == nil {
		t.Error("expected an out-of-range index to be rejected")
	}
	if err := l.Revoke(-1); err == nil {
		t.Error("expected a negative index to be rejected")
	}
}

// The encoded list must round-trip through zlib and base64url, because that is
// exactly what a consumer does to read it.
func TestEncodedListRoundTrips(t *testing.T) {
	l := New(64)
	for _, i := range []int{0, 7, 8, 63} {
		if err := l.Revoke(i); err != nil {
			t.Fatal(err)
		}
	}
	enc, err := l.encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		t.Fatalf("base64url decode: %v", err)
	}
	zr, err := zlib.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("zlib: %v", err)
	}
	defer func() { _ = zr.Close() }()
	bits, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	for _, i := range []int{0, 7, 8, 63} {
		if bits[i/8]&(1<<(i%8)) == 0 {
			t.Errorf("index %d should be set in the decoded bit string", i)
		}
	}
	if bits[1]&(1<<1) != 0 {
		t.Error("index 9 should not be set")
	}
}

func TestSignedListDeclaresOneBitPerEntry(t *testing.T) {
	l := New(16)
	key, chain := testKeyAndChain(t)
	tok, err := l.Sign("https://r.test", "https://r.test/status-list.jwt", key, chain, time.Hour, 7*24*time.Hour)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("expected a compact JWS, got %d parts", len(parts))
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var p map[string]any
	if err := json.Unmarshal(body, &p); err != nil {
		t.Fatal(err)
	}
	sl, ok := p["status_list"].(map[string]any)
	if !ok {
		t.Fatal("payload has no status_list object")
	}
	if sl["bits"].(float64) != 1 {
		t.Errorf("bits = %v, want 1", sl["bits"])
	}
	if p["sub"] != "https://r.test/status-list.jwt" {
		t.Errorf("sub = %v, want the status list URI", p["sub"])
	}
}

func decodePayload(t *testing.T, tok string) map[string]any {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("expected a compact JWS, got %d parts", len(parts))
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var p map[string]any
	if err := json.Unmarshal(body, &p); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSignSeparatesCacheTTLFromValidity(t *testing.T) {
	l := New(8)
	key, chain := testKeyAndChain(t)
	tok, err := l.Sign("https://r.test", "https://r.test/status-list.jwt", key, chain, time.Hour, 7*24*time.Hour)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	p := decodePayload(t, tok)
	iat, exp, ttl := int64(p["iat"].(float64)), int64(p["exp"].(float64)), int(p["ttl"].(float64))
	if ttl != 3600 {
		t.Errorf("ttl = %d, want 3600", ttl)
	}
	if got := exp - iat; got != 7*24*3600 {
		t.Errorf("exp-iat = %d, want one week", got)
	}
}

func TestSignCapsTTLAtValidity(t *testing.T) {
	l := New(8)
	key, chain := testKeyAndChain(t)
	tok, err := l.Sign("https://r.test", "https://r.test/status-list.jwt", key, chain, time.Hour, 10*time.Minute)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	p := decodePayload(t, tok)
	if ttl := int(p["ttl"].(float64)); ttl != 600 {
		t.Errorf("ttl = %d, want 600 (capped at validity)", ttl)
	}
	if _, err := l.Sign("https://r.test", "https://r.test/status-list.jwt", key, chain, time.Hour, 0); err == nil {
		t.Error("zero validity should be rejected")
	}
}
