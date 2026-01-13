package main

import (
	"time"

	"github.com/patrickmn/go-cache"
)

// Key type definitions
type KeyType string

const (
	KeyTypeEd25519  KeyType = "ed25519"
	KeyTypeECDSA    KeyType = "ecdsa-p256"
	KeyTypeRSAPSS   KeyType = "rsa-2048-pss"
	KeyTypeRSAPKCS1 KeyType = "rsa-2048-pkcs1"
	KeyTypeECDH     KeyType = "ecdh-p256"
)

// Unified key structures for better organization
type PublicKeyInfo struct {
	Key  []byte
	Type KeyType
}

type UnifiedKeyInfo struct {
	PublicKey     []byte      // Public key for asymmetric crypto
	KeyType       KeyType     // Type of key (ecdsa, rsa-2048, ed25519)
	SymmetricKey  []byte      // AES-256 key for symmetric encryption (if available)
	ServerPrivKey interface{} // Server's private key for ECDH (if applicable)
	HwKey         interface{}
}

// In-memory caches with consistent expiration times
const (
	defaultCacheExpiry = 3 * time.Hour
	cleanupInterval    = 10 * time.Minute
)

var (
	usersCache        = cache.New(defaultCacheExpiry, cleanupInterval) // Cache for user data
	accelKeys         = cache.New(defaultCacheExpiry, cleanupInterval) // Cache for unified acceleration keys
	tokensCache       = cache.New(defaultCacheExpiry, cleanupInterval) // Cache for tokens and associated hardware keys
	tpmAttestations   = cache.New(defaultCacheExpiry, cleanupInterval) // Cache for TPM attestations
	verifiedTPMTokens = cache.New(defaultCacheExpiry, cleanupInterval) // Cache for tokens with verified TPM
	aikChallenges     = cache.New(15*time.Minute, cleanupInterval)     // Cache for AIK makecredential challenges
	aiaCertCache      = cache.New(24*time.Hour, cleanupInterval)       // Cache for downloaded AIA certificates by URL
)

// ============ TPM Attestation Structures ============

// TPMInfo contains basic TPM information
type TPMInfo struct {
	Manufacturer    string `json:"manufacturer"`
	FirmwareVersion string `json:"firmware_version"`
	TPMVersion      uint32 `json:"tpm_version"`
	PlatformType    string `json:"platform_type"`
}

// TPMCertificateChain contains the EK certificate chain from TPM
type TPMCertificateChain struct {
	TPMInfo      TPMInfo           `json:"tpm_info"`
	EKCerts      []string          `json:"ek_certs,omitempty"`       // Additional EK certs (DER) if present
	EKNVCerts    []string          `json:"ek_nv_certs,omitempty"`    // Additional EK NV certs (DER) if present
	EKPub        string            `json:"ek_pub,omitempty"`         // Base64 encoded EK public key
	AIKPub       string            `json:"aik_pub,omitempty"`        // Base64 encoded AIK public key
	AIKName      string            `json:"aik_name,omitempty"`       // Base64 encoded AIK TPM2B_NAME
	EICACerts    []string          `json:"eica_certs,omitempty"`     // Base64 encoded embedded intermediate CA certs (optional)
	NVIndexBlobs map[string]string `json:"nv_index_blobs,omitempty"` // NV index hex -> raw bytes (base64)
}

// ============ AIK Registration (MakeCredential/ActivateCredential) ============

type AikChallengeRequest struct {
	CertChain TPMCertificateChain `json:"cert_chain"`
	IdBinding string              `json:"id_binding"`           // Base64 (PCP idBinding blob)
	NonceSHA1 string              `json:"nonce_sha1,omitempty"` // Optional, base64
}

type AikChallengeResponse struct {
	ChallengeID    string `json:"challenge_id"`
	ActivationBlob string `json:"activation_blob"` // Base64: TPM2B_ID_OBJECT || TPM2B_ENCRYPTED_SECRET
}

type AikActivateRequest struct {
	ChallengeID string `json:"challenge_id"`
	Secret      string `json:"secret"` // Base64: recovered secret bytes
}

type aikChallengeState struct {
	ExpectedSecret []byte
	CreatedAt      time.Time
}

// KeyAttestationRequest contains key attestation data for verification
type KeyAttestationRequest struct {
	KeyType     string              `json:"key_type"`
	CertifyInfo string              `json:"certify_info,omitempty"` // Base64 encoded TPMS_ATTEST (TPM2_Certify output)
	Signature   string              `json:"signature,omitempty"`    // Base64 encoded signature
	AIKPub      string              `json:"aik_pub,omitempty"`      // Base64 encoded AIK public key
	KeyName     string              `json:"key_name,omitempty"`     // Base64 encoded key TPM2B_NAME
	KeyBlob     string              `json:"key_blob,omitempty"`     // Base64 encoded opaque key blob (optional)
	CertChain   TPMCertificateChain `json:"cert_chain,omitempty"`   // Certificate chain for verification
}

// TPMVerificationResult contains the result of TPM verification
type TPMVerificationResult struct {
	Verified         bool     `json:"verified"`
	TPMManufacturer  string   `json:"tpm_manufacturer,omitempty"`
	TPMVersion       uint32   `json:"tpm_version,omitempty"`
	EKCertValid      bool     `json:"ek_cert_valid"`
	AIKValid         bool     `json:"aik_valid"`
	KeyInTPM         bool     `json:"key_in_tpm"`
	Warnings         []string `json:"warnings,omitempty"`
	VerificationTime string   `json:"verification_time"`
}

// Known TPM manufacturer IDs (from TCG registry)
// Maps both hex IDs and ASCII codes to friendly names
var knownTPMManufacturers = map[string]string{
	// Hex format (TCG standard)
	"414d4400": "AMD",
	"41544d4c": "Atmel",
	"4252434d": "Broadcom",
	"48504500": "HPE",
	"49424d00": "IBM",
	"49465800": "Infineon",
	"494e5443": "Intel",
	"4c454e00": "Lenovo",
	"4d534654": "Microsoft",
	"4e534d20": "National Semiconductor",
	"4e545a00": "Nationz",
	"4e544300": "Nuvoton",
	"51434f4d": "Qualcomm",
	"534d5343": "SMSC",
	"53544d20": "STMicroelectronics",
	"534d534e": "Samsung",
	"534e5300": "Sinosun",
	"54584e00": "Texas Instruments",
	"57454300": "Winbond",
	"524f4343": "Fuzhou Rockchip",
	"474f4f47": "Google",
	// ASCII format (as returned by some clients)
	"amd":  "AMD",
	"intc": "Intel",
	"ibm":  "IBM",
	"msft": "Microsoft",
	"ifx":  "Infineon",
	"stm":  "STMicroelectronics",
	"ntc":  "Nuvoton",
	"ntz":  "Nationz",
	"wec":  "Winbond",
	"qcom": "Qualcomm",
	"smsc": "SMSC",
	"smsn": "Samsung",
	"len":  "Lenovo",
	"hpe":  "HPE",
	"goog": "Google",
	"rocc": "Fuzhou Rockchip",
}
