// Package trustlistmirror queries
// https://github.com/section42/hcert-trustlist-mirror for trustlists of various
// EU member states.
package trustlistmirror

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
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

	// TrustlistNL refers to the mirrored version of the Dutch Trustlist.
	TrustlistNL = &List{
		URL:    "https://raw.githubusercontent.com/section42/hcert-trustlist-mirror/main/trustlist_nl.raw.keys.json",
		decode: decodeNL,
	}

	// TrustlistSE refers to the mirrored version of the Swedish Trustlist.
	TrustlistSE = &List{
		URL:    "https://raw.githubusercontent.com/section42/hcert-trustlist-mirror/main/trustlist_se.min.json",
		decode: decodeDE,
	}

	// TrustlistCH refers to the mirrored version of the Swiss Trustlist.
	TrustlistCH = &List{
		URL:    "https://raw.githubusercontent.com/section42/hcert-trustlist-mirror/main/trustlist_ch.min.json",
		decode: decodeCH,
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

// pubkeyOnlyCertificateProvider implements the coronaqr.CertificateProvider interface.
type pubkeyOnlyCertificateProvider struct {
	pubKeys map[string]crypto.PublicKey
}

// GetPublicKey implements the coronaqr.PublicKeyProvider interface.
func (c *pubkeyOnlyCertificateProvider) GetPublicKey(_ string, kid []byte) (crypto.PublicKey, error) {
	kidNormalized := base64.StdEncoding.EncodeToString(kid)
	if pubKey, ok := c.pubKeys[kidNormalized]; ok {
		return pubKey, nil
	}
	return nil, fmt.Errorf("public key for kid=%s not found", kidNormalized)
}

func (c *pubkeyOnlyCertificateProvider) String() string {
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
	return &pubkeyOnlyCertificateProvider{pubKeys: pubKeys}, nil
}

func decodeNL(body []byte) (coronaqr.PublicKeyProvider, error) {
	type certificate struct {
		PublicKeyPEM string `json:"subjectPk"`
	}
	var certificates struct {
		EUKeys map[string][]certificate `json:"eu_keys"`
	}
	if err := json.Unmarshal(body, &certificates); err != nil {
		return nil, err
	}
	pubKeys := make(map[string]crypto.PublicKey)
	for kid, certs := range certificates.EUKeys {
		for _, cert := range certs {
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
	}
	return &pubkeyOnlyCertificateProvider{pubKeys: pubKeys}, nil
}

// see https://github.com/admin-ch/CovidCertificate-SDK-Kotlin/blob/883f4b40b4a617485e3527d8dbe833070c6440b5/src/main/java/ch/admin/bag/covidcertificate/sdk/core/models/trustlist/Jwk.kt#L28
type chCertificate struct {
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func pubKeyFromCHCertificate(cert chCertificate) (crypto.PublicKey, error) {
	if cert.Alg == "ES256" {
		if cert.Crv == "" || cert.X == "" || cert.Y == "" {
			return nil, errors.New("ES256 key missing Crv, X or Y field")
		}

		var curve elliptic.Curve
		switch cert.Crv {
		case "P-224":
			curve = elliptic.P224()
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unknown curve type %q", cert.Crv)
		}

		pubKey := &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int),
			Y:     new(big.Int),
		}

		decX, err := base64.StdEncoding.DecodeString(cert.X)
		if err != nil {
			return nil, errors.New("ES256 key has malformed X")
		}
		pubKey.X.SetBytes(decX)

		decY, err := base64.StdEncoding.DecodeString(cert.Y)
		if err != nil {
			return nil, errors.New("ES256 key has malformed X")
		}
		pubKey.Y.SetBytes(decY)

		return pubKey, nil
	} else if cert.Alg == "RS256" {
		if cert.N == "" || cert.E == "" {
			return nil, errors.New("RS256 key missing N or E field")
		}

		decE, err := base64.StdEncoding.DecodeString(cert.E)
		if err != nil {
			return nil, errors.New("RS256 key has malformed exponent")
		}
		if len(decE) < 4 {
			ndata := make([]byte, 4)
			copy(ndata[4-len(decE):], decE)
			decE = ndata
		}

		pubKey := &rsa.PublicKey{
			N: new(big.Int),
			E: int(binary.BigEndian.Uint32(decE[:])),
		}

		decN, err := base64.StdEncoding.DecodeString(cert.N)
		if err != nil {
			return nil, errors.New("RS256 key has malformed N")
		}
		pubKey.N.SetBytes(decN)

		return pubKey, nil
	} else {
		return nil, fmt.Errorf("unknown key algorithm %q", cert.Alg)
	}
}

// The swiss trust list uses an almost-JWK format, but not quite: the Kty (key
// type) field is not present, instead the Alg (algorithm) field is present.
//
// Unfortunately, none of the Go jwk implementations I tried could decode these
// without modifications:
//
// - github.com/lestrrat-go/jwx/jwk needs the Kty field
//
// - github.com/mendsley/gojwk needs the Kty field and uses base64 URL encoding
// instead of base64 standard encoding
func decodeCH(body []byte) (coronaqr.PublicKeyProvider, error) {
	certificates := make(map[string][]chCertificate)
	if err := json.Unmarshal(body, &certificates); err != nil {
		return nil, err
	}
	pubKeys := make(map[string]crypto.PublicKey)
	for kid, certs := range certificates {
		// Normalize kid, might be shortened (padding with = characters).
		kidB, err := base64.StdEncoding.DecodeString(kid)
		if err != nil {
			return nil, err
		}
		kidNormalized := base64.StdEncoding.EncodeToString(kidB)

		pubKey, err := pubKeyFromCHCertificate(certs[0])
		if err != nil {
			return nil, err
		}

		pubKeys[kidNormalized] = pubKey
	}
	return &pubkeyOnlyCertificateProvider{pubKeys: pubKeys}, nil
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
