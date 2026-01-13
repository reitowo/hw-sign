package main

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/patrickmn/go-cache"
)

// AIA (Authority Information Access) allowed hosts for certificate fetching
var aiaAllowedHosts = map[string]bool{
	// Intel ODCA (PTT)
	"tsci.intel.com": true,
	"www.intel.com":  true,
	// AMD fTPM (optional; varies)
	"ftpm.amd.com": true,
	// Common vendor PKI endpoints (optional)
	"pki.infineon.com": true,
}

var aiaHTTPClient = &http.Client{
	Timeout: 10 * time.Second,
}

// Intel ODCA Root CA (On-Die CA Root Cert Signing)
// Downloaded from: https://tsci.intel.com/content/OnDieCA/certs/OnDie_CA_RootCA_Certificate.cer
// Subject: CN=www.intel.com, OU=OnDie CA Root Cert Signing, O=Intel Corporation, L=Santa Clara, S=CA, C=US
// Valid: 2019-04-03 to 2050-01-01
// This is the root of trust for Intel TPM EK certificates (CSME/PTT)
const intelODCARootCAPEM = `-----BEGIN CERTIFICATE-----
MIICujCCAj6gAwIBAgIUPLLiHTrwySRtWxR4lxKLlu7MJ7wwDAYIKoZIzj0EAwMF
ADCBiTELMAkGA1UEBgwCVVMxCzAJBgNVBAgMAkNBMRQwEgYDVQQHDAtTYW50YSBD
bGFyYTEaMBgGA1UECgwRSW50ZWwgQ29ycG9yYXRpb24xIzAhBgNVBAsMGk9uRGll
IENBIFJvb3QgQ2VydCBTaWduaW5nMRYwFAYDVQQDDA13d3cuaW50ZWwuY29tMB4X
DTE5MDQwMzAwMDAwMFoXDTQ5MTIzMTIzNTk1OVowgYkxCzAJBgNVBAYMAlVTMQsw
CQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNVBAoMEUludGVs
IENvcnBvcmF0aW9uMSMwIQYDVQQLDBpPbkRpZSBDQSBSb290IENlcnQgU2lnbmlu
ZzEWMBQGA1UEAwwNd3d3LmludGVsLmNvbTB2MBAGByqGSM49AgEGBSuBBAAiA2IA
BK8SfB2UflvXZqb5Kc3+lokrABHWazvNER2axPURP64HILkXChPB0OEX5hLB7Okw
7Dy6oFqB5tQVDupgfvUX/SgYBEaDdG5rCVFrGAis6HX5TA2ewQmj14r2ncHBgnpp
B6NjMGEwHwYDVR0jBBgwFoAUtFjJ9uQIQKPyWMg5eG6ujgqNnDgwDwYDVR0TAQH/
BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFLRYyfbkCECj8ljIOXhu
ro4KjZw4MAwGCCqGSM49BAMDBQADaAAwZQIxAP9B4lFF86uvpHmkcp61cWaU565a
yE3p7ezu9haLE/lPLh5hFQfmTi1nm/sG3JEXMQIwNpKfHoDmUTrUyezhhfv3GG+1
CqBXstmCYH40buj9jKW3pHWc71s9arEmPWli7I8U
-----END CERTIFICATE-----`

// builtinTPMRootCAs returns a pool of known TPM manufacturer root CAs
func builtinTPMRootCAs() *x509.CertPool {
	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM([]byte(intelODCARootCAPEM)); ok {
		debugLog("builtinTPMRootCAs", "Intel ODCA Root CA loaded")
	}
	// Add more manufacturer root CAs here as needed (AMD, Infineon, etc.)
	return pool
}

// fetchAiaIssuerChain fetches the certificate chain via AIA URLs
func fetchAiaIssuerChain(leaf *x509.Certificate, maxDepth int) ([]*x509.Certificate, []string) {
	warnings := []string{}
	if leaf == nil {
		return nil, warnings
	}
	debugLog("fetchAIA", "Starting AIA chain fetch for: %s", leaf.Subject.CommonName)

	seen := map[string]bool{}
	cur := leaf
	out := []*x509.Certificate{}

	for depth := 0; depth < maxDepth; depth++ {
		// If self-signed-ish, stop
		if cur.Subject.String() == cur.Issuer.String() {
			debugLog("fetchAIA", "Reached self-signed cert at depth %d: %s", depth, cur.Subject.CommonName)
			break
		}
		if len(cur.IssuingCertificateURL) == 0 {
			debugLog("fetchAIA", "No AIA URL at depth %d for: %s (issuer: %s)", depth, cur.Subject.CommonName, cur.Issuer.CommonName)
			break
		}
		u := cur.IssuingCertificateURL[0]
		if seen[u] {
			break
		}
		seen[u] = true

		debugLog("fetchAIA", "Fetching AIA URL: %s", u)
		certs, warn, err := fetchCertsFromAiaURL(u)
		warnings = append(warnings, warn...)
		if err != nil {
			debugLog("fetchAIA", "AIA fetch error: %v", err)
			break
		}
		if len(certs) == 0 {
			debugLog("fetchAIA", "AIA returned no certs")
			break
		}
		debugLog("fetchAIA", "AIA returned %d cert(s), first: %s", len(certs), certs[0].Subject.CommonName)
		// pick the first; if multiple returned, we still add all
		for _, c := range certs {
			out = append(out, c)
		}
		cur = certs[0]
	}
	debugLog("fetchAIA", "AIA chain fetch complete, got %d certs total", len(out))
	return out, warnings
}

func fetchCertsFromAiaURL(raw string) ([]*x509.Certificate, []string, error) {
	warnings := []string{}
	if v, ok := aiaCertCache.Get(raw); ok {
		return v.([]*x509.Certificate), warnings, nil
	}
	uu, err := url.Parse(raw)
	if err != nil {
		return nil, warnings, err
	}
	if uu.Scheme != "https" {
		return nil, warnings, fmt.Errorf("AIA URL must be https: %s", raw)
	}
	host := strings.ToLower(uu.Hostname())
	if !aiaAllowedHosts[host] {
		return nil, warnings, fmt.Errorf("AIA host not allowlisted: %s", host)
	}

	resp, err := aiaHTTPClient.Get(raw)
	if err != nil {
		return nil, warnings, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, warnings, fmt.Errorf("AIA fetch status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
	if err != nil {
		return nil, warnings, err
	}
	// Usually DER cert. Try ParseCertificate first, then ParseCertificates.
	if c, err := x509.ParseCertificate(body); err == nil {
		certs := []*x509.Certificate{c}
		aiaCertCache.Set(raw, certs, cache.DefaultExpiration)
		return certs, warnings, nil
	}
	if cs, err := x509.ParseCertificates(body); err == nil && len(cs) > 0 {
		aiaCertCache.Set(raw, cs, cache.DefaultExpiration)
		return cs, warnings, nil
	}
	// Might be PEM
	if cs, err := x509.ParseCertificates(pemToDerAll(body)); err == nil && len(cs) > 0 {
		aiaCertCache.Set(raw, cs, cache.DefaultExpiration)
		return cs, warnings, nil
	}
	warnings = append(warnings, "AIA response was not a parsable certificate")
	return nil, warnings, errors.New("AIA response not certificate")
}

func pemToDerAll(b []byte) []byte {
	// Minimal PEM stripper: if it isn't PEM, return original bytes.
	s := string(b)
	if !strings.Contains(s, "BEGIN CERTIFICATE") {
		return b
	}
	lines := []string{}
	for _, ln := range strings.Split(s, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "-----BEGIN") || strings.HasPrefix(ln, "-----END") {
			continue
		}
		lines = append(lines, ln)
	}
	der, err := base64.StdEncoding.DecodeString(strings.Join(lines, ""))
	if err != nil {
		return b
	}
	return der
}

func splitConcatenatedDerCerts(data []byte) ([]*x509.Certificate, []string) {
	warnings := []string{}
	out := []*x509.Certificate{}

	rest := data
	for len(rest) > 0 {
		c, err := x509.ParseCertificate(rest)
		if err != nil {
			// Can't parse; stop
			break
		}
		out = append(out, c)
		// DER certs are length-prefixed by ASN.1 SEQUENCE. We rely on parsing.
		// We advance by c.Raw length if available.
		if len(c.Raw) == 0 {
			break
		}
		rest = rest[len(c.Raw):]
	}

	if len(out) == 0 {
		warnings = append(warnings, "Failed to split concatenated DER certs")
	}
	return out, warnings
}
