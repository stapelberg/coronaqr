// Package trustlistmirror queries
// https://github.com/section42/hcert-trustlist-mirror for trustlists of various
// EU member states.
package trustlistmirror

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/stapelberg/coronaqr"
)

// A List refers to a mirrored version of an EU member states Trustlist.
type List struct {
	URL    string
	decode func(body []byte) (coronaqr.PublicKeyProvider, error)
}

var (
	// TrustlistDE refers to the mirrored version of the German Trustlist.
	TrustlistDE = &List{
		URL:    "https://raw.githubusercontent.com/section42/hcert-trustlist-mirror/main/trustlist_de.min.json",
		decode: decodeDE,
	}

	// TrustlistAT refers to the mirrored version of the Austrian Trustlist.
	TrustlistAT = &List{
		URL:    "https://raw.githubusercontent.com/section42/hcert-trustlist-mirror/main/trustlist_at.min.json",
		decode: decodeDE,
	}

	// TrustlistFR refers to the mirrored version of the French Trustlist.
	TrustlistFR = &List{
		URL:    "https://raw.githubusercontent.com/section42/hcert-trustlist-mirror/main/trustlist_fr.min.json",
		decode: decodeFR,
	}
)

type certificateProvider struct {
	certs map[string]*x509.Certificate
}

// GetPublicKey implements the coronaqr.PublicKeyProvider interface.
func (c *certificateProvider) GetPublicKey(_ string, kid []byte) (crypto.PublicKey, error) {
	kidNormalized := base64.StdEncoding.EncodeToString(kid)
	if cert, ok := c.certs[kidNormalized]; ok {
		return cert.PublicKey, nil
	}
	return nil, fmt.Errorf("public key for kid=%s not found", kidNormalized)
}

// GetCertificate implements the coronaqr.CertificateProvider interface.
func (c *certificateProvider) GetCertificate(_ string, kid []byte) (*x509.Certificate, error) {
	kidNormalized := base64.StdEncoding.EncodeToString(kid)
	if cert, ok := c.certs[kidNormalized]; ok {
		return cert, nil
	}
	return nil, fmt.Errorf("certificate for kid=%s not found", kidNormalized)
}

func (c *certificateProvider) String() string {
	// TODO: display list of countries
	return fmt.Sprintf("%d certificates", len(c.certs))
}

func decodeDE(body []byte) (coronaqr.PublicKeyProvider, error) {
	type certificate struct {
		Kid     string `json:"kid"`
		RawData string `json:"rawData"`
	}
	var certificates struct {
		Certificates []certificate `json:"certificates"`
	}
	if err := json.Unmarshal(body, &certificates); err != nil {
		return nil, err
	}
	certs := make(map[string]*x509.Certificate)
	for _, cert := range certificates.Certificates {
		// Normalize kid, might be shortened (padding with = characters).
		kid, err := base64.StdEncoding.DecodeString(cert.Kid)
		if err != nil {
			return nil, err
		}
		kidNormalized := base64.StdEncoding.EncodeToString(kid)
		certB, err := base64.StdEncoding.DecodeString(cert.RawData)
		if err != nil {
			return nil, err
		}
		cert, err := x509.ParseCertificate(certB)
		if err != nil {
			return nil, err
		}
		certs[kidNormalized] = cert
	}
	return &certificateProvider{certs: certs}, nil
}

// frenchCertificateProvider implements the coronaqr.CertificateProvider interface.
type frenchCertificateProvider struct {
	pubKeys map[string]crypto.PublicKey
}

// GetPublicKey implements the coronaqr.PublicKeyProvider interface.
func (c *frenchCertificateProvider) GetPublicKey(_ string, kid []byte) (crypto.PublicKey, error) {
	kidNormalized := base64.StdEncoding.EncodeToString(kid)
	if pubKey, ok := c.pubKeys[kidNormalized]; ok {
		return pubKey, nil
	}
	return nil, fmt.Errorf("public key for kid=%s not found", kidNormalized)
}

func (c *frenchCertificateProvider) String() string {
	return fmt.Sprintf("%d public keys", len(c.pubKeys))
}

func decodeFR(body []byte) (coronaqr.PublicKeyProvider, error) {
	type certificate struct {
		PublicKeyPEM string `json:"publicKeyPEM"`
	}
	certificates := make(map[string]certificate)
	if err := json.Unmarshal(body, &certificates); err != nil {
		return nil, err
	}
	pubKeys := make(map[string]crypto.PublicKey)
	for kid, cert := range certificates {
		// Normalize kid, might be shortened (padding with = characters).
		kidB, err := base64.StdEncoding.DecodeString(kid)
		if err != nil {
			return nil, err
		}
		kidNormalized := base64.StdEncoding.EncodeToString(kidB)

		certB, err := base64.StdEncoding.DecodeString(cert.PublicKeyPEM)
		if err != nil {
			return nil, err
		}
		pub, err := x509.ParsePKIXPublicKey(certB)
		if err != nil {
			return nil, err
		}
		pubKeys[kidNormalized] = pub
	}
	return &frenchCertificateProvider{pubKeys: pubKeys}, nil
}

// NewCertificateProvider downloads the specified TrustList over the internet
// (usually a few hundred kilobytes in size) and returns a CertificateProvider
// to use for verifying covid certificates.
func NewCertificateProvider(ctx context.Context, list *List) (coronaqr.PublicKeyProvider, error) {
	req, err := http.NewRequest("GET", list.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("User-Agent", "https://github.com/stapelberg/coronaqr")
	req = req.WithContext(ctx)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status code: got %v, want %v", resp.Status, http.StatusOK)
	}
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return list.decode(b)
}
