// Package wrprc mints Wallet-Relying Party Registration Certificates (WRPRCs)
// per ETSI TS 119 475 V1.2.1.
//
// A WRPRC is a signed JWT with media type "rc-wrp+jwt" carrying the WRP's
// registered entitlements and, for providers, the attestations it is registered
// to issue. Field spellings here follow V1.2.1 (Annex C), which differs from
// V1.1.1 in several places — see FieldNotes.
package wrprc

// FieldNotes records where TS 119 475 V1.2.1 differs from V1.1.1, because
// go-trust's rpcert package currently models V1.1.1 and will silently
// mis-parse a V1.2.1 document:
//
//	V1.1.1                      V1.2.1 (this package)
//	------------------------    -----------------------------
//	sub: {legal_name, id, ...}  sub: "LEIXG-..." (flat string)
//	                            sub_ln / sub_gn / sub_fn
//	service                     srv_description
//	credentials[].claims        credentials[].claim
//	provided_attestations       provides_attestations
//	(absent)                    supervisory_authority
const FieldNotes = "TS 119 475 V1.2.1 field spellings; see package doc"

// Entitlement URIs per TS 119 475 V1.2.1 Annex A.2.
const (
	EntitlementServiceProvider           = "https://uri.etsi.org/19475/Entitlement/Service_Provider"
	EntitlementQEAAProvider              = "https://uri.etsi.org/19475/Entitlement/QEAA_Provider"
	EntitlementNonQEAAProvider           = "https://uri.etsi.org/19475/Entitlement/Non_Q_EAA_Provider"
	EntitlementPUBEAAProvider            = "https://uri.etsi.org/19475/Entitlement/PUB_EAA_Provider"
	EntitlementPIDProvider               = "https://uri.etsi.org/19475/Entitlement/PID_Provider"
	EntitlementQCertForESealProvider     = "https://uri.etsi.org/19475/Entitlement/QCert_for_ESeal_Provider"
	EntitlementQCertForESigProvider      = "https://uri.etsi.org/19475/Entitlement/QCert_for_ESig_Provider"
	EntitlementRQSealCDsProvider         = "https://uri.etsi.org/19475/Entitlement/rQSealCDs_Provider"
	EntitlementRQSigCDsProvider          = "https://uri.etsi.org/19475/Entitlement/rQSigCDs_Provider"
	EntitlementESigESealCreationProvider = "https://uri.etsi.org/19475/Entitlement/ESig_ESeal_Creation_Provider"
)

// ProviderEntitlements are the entitlements that make a WRP an issuer of PIDs or
// attestations. GEN-5.2.4-05 attaches provides_attestations to exactly these.
var ProviderEntitlements = []string{
	EntitlementPIDProvider,
	EntitlementQEAAProvider,
	EntitlementNonQEAAProvider,
	EntitlementPUBEAAProvider,
}

// IsProviderEntitlement reports whether uri denotes a PID or attestation provider.
func IsProviderEntitlement(uri string) bool {
	for _, e := range ProviderEntitlements {
		if e == uri {
			return true
		}
	}
	return false
}

// PolicyOIDWRPRC is the standard WRPRC certificate policy identifier (OVR-6.1.3-01).
const PolicyOIDWRPRC = "0.4.0.19475.3.1"

// MediaType is the WRPRC JWT media type (GEN-5.2.2-01).
const MediaType = "rc-wrp+jwt"

// MultiLangString is a localised string entry (class B.2.6).
type MultiLangString struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

// Claim is a single claim path within a credential query.
type Claim struct {
	Path []string `json:"path"`
}

// Credential is an entry of `credentials` or `provides_attestations`
// (Tables 8 and 9). Note the singular `claim` member — V1.2.1 Annex C.
type Credential struct {
	Format string         `json:"format"`
	Meta   map[string]any `json:"meta,omitempty"`
	Claim  []Claim        `json:"claim,omitempty"`
}

// StatusList is the `status.status_list` object (Table 7).
type StatusList struct {
	Idx int    `json:"idx"`
	URI string `json:"uri"`
}

// Status wraps StatusList.
type Status struct {
	StatusList StatusList `json:"status_list"`
}

// SupervisoryAuthority is the V1.2.1 `supervisory_authority` object.
type SupervisoryAuthority struct {
	Email string `json:"email,omitempty"`
	Phone string `json:"phone,omitempty"`
	URI   string `json:"uri,omitempty"`
}

// Payload is a WRPRC JWT payload per TS 119 475 V1.2.1 Tables 7-10.
type Payload struct {
	Name           string              `json:"name"`
	Sub            string              `json:"sub"`
	SubLegalName   string              `json:"sub_ln,omitempty"`
	SubGivenName   string              `json:"sub_gn,omitempty"`
	SubFamilyName  string              `json:"sub_fn,omitempty"`
	Country        string              `json:"country,omitempty"`
	RegistryURI    string              `json:"registry_uri,omitempty"`
	SrvDescription [][]MultiLangString `json:"srv_description,omitempty"`
	Entitlements   []string            `json:"entitlements"`

	// ProvidesAttestations is populated for provider entitlements only
	// (GEN-5.2.4-05, Table 8).
	ProvidesAttestations []Credential `json:"provides_attestations,omitempty"`
	// Credentials is the service-provider side (Table 9) — what the WRP may request.
	Credentials []Credential `json:"credentials,omitempty"`

	Purpose              []MultiLangString     `json:"purpose,omitempty"`
	PrivacyPolicy        string                `json:"privacy_policy,omitempty"`
	InfoURI              string                `json:"info_uri,omitempty"`
	SupportURI           string                `json:"support_uri,omitempty"`
	SupervisoryAuthority *SupervisoryAuthority `json:"supervisory_authority,omitempty"`
	PublicBody           bool                  `json:"public_body,omitempty"`
	PolicyID             []string              `json:"policy_id,omitempty"`
	CertificatePolicy    string                `json:"certificate_policy,omitempty"`
	IssuedAt             int64                 `json:"iat"`
	ExpiresAt            int64                 `json:"exp,omitempty"`
	Status               *Status               `json:"status,omitempty"`
}
