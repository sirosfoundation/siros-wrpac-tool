package tsl

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"math/big"

	"github.com/beevik/etree"
	"github.com/moov-io/signedxml"
)

// XMLDSig algorithm and transform URIs.
const (
	algEnvelopedSignature = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
	algExcC14N            = "http://www.w3.org/2001/10/xml-exc-c14n#"

	algECDSASHA256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
	algECDSASHA384 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
	algECDSASHA512 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"
	algRSASHA256   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"

	digestSHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
	digestSHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384"
	digestSHA512 = "http://www.w3.org/2001/04/xmlenc#sha512"
)

// signEnveloped produces an enveloped XMLDSig signature over the whole document.
//
// signedxml's own Signer is not used to produce the signature value: its
// algorithm table has ECDSA commented out, and the keys this tool issues are
// ECDSA P-256, so that path cannot sign a deployment's own list. Its exported
// canonicalization is used, though — exclusive c14n is the part that is hard to
// get right and must agree byte for byte with every verifier, so reimplementing
// it would be the actual risk.
//
// The reference is the whole document (URI="") with the enveloped-signature
// transform, which is what every eIDAS trusted list uses and what a TS 119 612
// consumer looks for.
func signEnveloped(doc []byte, key crypto.Signer, chain []*x509.Certificate) ([]byte, error) {
	if len(chain) == 0 {
		return nil, fmt.Errorf("tsl: no signing certificate chain")
	}
	sigAlg, digestAlg, hash, err := algorithmsFor(key.Public())
	if err != nil {
		return nil, err
	}

	parsed := etree.NewDocument()
	if rerr := parsed.ReadFromBytes(doc); rerr != nil {
		return nil, fmt.Errorf("tsl: reparse for signing: %w", rerr)
	}
	root := parsed.Root()
	if root == nil {
		return nil, fmt.Errorf("tsl: document has no root element to sign")
	}

	signature := signatureTemplate(root, sigAlg, digestAlg, chain)

	// The digest is over the document with the signature removed - that is what
	// the enveloped-signature transform means, and computing it over the
	// document including the (still empty) signature would produce a reference
	// no verifier can reproduce.
	digest, err := referenceDigest(parsed, hash)
	if err != nil {
		return nil, err
	}
	mustFind(signature, "./SignedInfo/Reference/DigestValue").SetText(digest)

	signedInfo := mustFind(signature, "./SignedInfo")
	canonSignedInfo, err := signedxml.CanonicalizationAlgorithms[algExcC14N].ProcessElement(signedInfo, "")
	if err != nil {
		return nil, fmt.Errorf("tsl: canonicalize SignedInfo: %w", err)
	}

	value, err := signBytes(key, hash, []byte(canonSignedInfo))
	if err != nil {
		return nil, err
	}
	mustFind(signature, "./SignatureValue").SetText(base64.StdEncoding.EncodeToString(value))

	// Deliberately not re-indented: the reference digest was computed over this
	// document's exact bytes, and reformatting afterwards would change what a
	// verifier canonicalizes without changing what was signed.
	out, err := parsed.WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("tsl: serialise signed document: %w", err)
	}
	return out, nil
}

// referenceDigest applies the enveloped-signature transform followed by
// exclusive canonicalization, and hashes the result.
func referenceDigest(doc *etree.Document, hash crypto.Hash) (string, error) {
	transformed := doc.Copy()
	if root := transformed.Root(); root != nil {
		for _, sig := range root.FindElements("./Signature") {
			root.RemoveChild(sig)
		}
		for _, sig := range root.FindElements("./ds:Signature") {
			root.RemoveChild(sig)
		}
	}
	canon, err := signedxml.CanonicalizationAlgorithms[algExcC14N].ProcessDocument(transformed, "")
	if err != nil {
		return "", fmt.Errorf("tsl: canonicalize document: %w", err)
	}
	h := hash.New()
	h.Write([]byte(canon))
	return base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}

// signatureTemplate appends the ds:Signature skeleton and returns it.
//
// The certificate chain goes into ds:KeyInfo so a consumer can identify the
// signer without having been handed the certificate out of band.
func signatureTemplate(root *etree.Element, sigAlg, digestAlg string, chain []*x509.Certificate) *etree.Element {
	sig := root.CreateElement("ds:Signature")
	sig.CreateAttr("xmlns:ds", nsDS)

	signedInfo := sig.CreateElement("ds:SignedInfo")
	signedInfo.CreateElement("ds:CanonicalizationMethod").CreateAttr("Algorithm", algExcC14N)
	signedInfo.CreateElement("ds:SignatureMethod").CreateAttr("Algorithm", sigAlg)

	ref := signedInfo.CreateElement("ds:Reference")
	ref.CreateAttr("URI", "")
	transforms := ref.CreateElement("ds:Transforms")
	transforms.CreateElement("ds:Transform").CreateAttr("Algorithm", algEnvelopedSignature)
	transforms.CreateElement("ds:Transform").CreateAttr("Algorithm", algExcC14N)
	ref.CreateElement("ds:DigestMethod").CreateAttr("Algorithm", digestAlg)
	ref.CreateElement("ds:DigestValue")

	sig.CreateElement("ds:SignatureValue")

	x509Data := sig.CreateElement("ds:KeyInfo").CreateElement("ds:X509Data")
	for _, c := range chain {
		x509Data.CreateElement("ds:X509Certificate").
			SetText(base64.StdEncoding.EncodeToString(c.Raw))
	}
	return sig
}

// signBytes signs data, producing the raw form XMLDSig expects.
//
// ECDSA signatures are the fixed-width r||s concatenation of RFC 4051, not the
// ASN.1 DER sequence crypto/ecdsa returns — the same distinction the JAdES
// signer in pkg/jws has to make. Getting this wrong produces a signature that
// looks well-formed and verifies nowhere.
func signBytes(key crypto.Signer, hash crypto.Hash, data []byte) ([]byte, error) {
	h := hash.New()
	h.Write(data)
	digest := h.Sum(nil)

	sig, err := key.Sign(rand.Reader, digest, hash)
	if err != nil {
		return nil, fmt.Errorf("tsl: sign: %w", err)
	}

	pub, isECDSA := key.Public().(*ecdsa.PublicKey)
	if !isECDSA {
		return sig, nil
	}
	var parsed struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(sig, &parsed); err != nil {
		// Some signers (notably PKCS#11 tokens) already return r||s.
		if expected := 2 * keyByteLen(pub.Curve); len(sig) == expected {
			return sig, nil
		}
		return nil, fmt.Errorf("tsl: unrecognised ECDSA signature encoding: %w", err)
	}
	size := keyByteLen(pub.Curve)
	out := make([]byte, 2*size)
	parsed.R.FillBytes(out[:size])
	parsed.S.FillBytes(out[size:])
	return out, nil
}

func keyByteLen(curve elliptic.Curve) int {
	return (curve.Params().BitSize + 7) / 8
}

// algorithmsFor picks the XMLDSig URIs and hash matching the signing key.
//
// Derived from the key rather than taken as a parameter: the signature has to
// verify against the certificate published in KeyInfo, so there is only one
// correct answer and no reason to let a caller get it wrong.
func algorithmsFor(pub crypto.PublicKey) (sigAlg, digestAlg string, hash crypto.Hash, err error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return algECDSASHA256, digestSHA256, crypto.SHA256, nil
		case elliptic.P384():
			return algECDSASHA384, digestSHA384, crypto.SHA384, nil
		case elliptic.P521():
			return algECDSASHA512, digestSHA512, crypto.SHA512, nil
		default:
			return "", "", 0, fmt.Errorf("tsl: unsupported ECDSA curve %s", k.Curve.Params().Name)
		}
	case *rsa.PublicKey:
		return algRSASHA256, digestSHA256, crypto.SHA256, nil
	default:
		return "", "", 0, fmt.Errorf("tsl: unsupported signing key type %T", pub)
	}
}

// mustFind returns the single element at path. The paths used here are all in
// the template this file just created, so a miss is a programming error rather
// than anything a caller can cause.
func mustFind(el *etree.Element, path string) *etree.Element {
	found := el.FindElement(path)
	if found == nil {
		panic("tsl: signature template is missing " + path)
	}
	return found
}
