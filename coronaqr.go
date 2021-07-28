// Package coronaqr provides a decoder for EU Digital COVID Certificate (EUDCC)
// QR code data.
//
// See https://github.com/eu-digital-green-certificates for the specs, testdata,
// etc.
package coronaqr

import (
	"bytes"
	"compress/zlib"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/minvws/base45-go/eubase45"
	"github.com/veraison/go-cose"
)

// Decoded is a EU Digital COVID Certificate (EUDCC) that has been decoded and
// possibly verified.
type Decoded struct {
	Cert       CovidCert
	IssuedAt   time.Time
	Expiration time.Time

	// SignedBy is the x509 certificate whose signature of the COVID Certificate
	// has been successfully verified, if Verify() was used and the trustlist
	// makes available certificates (as opposed to just public keys).
	SignedBy *x509.Certificate
}

// see https://github.com/ehn-dcc-development/ehn-dcc-schema

type CovidCert struct {
	Version         string           `cbor:"ver" json:"ver"`
	PersonalName    Name             `cbor:"nam" json:"nam"`
	DateOfBirth     string           `cbor:"dob" json:"dob"`
	VaccineRecords  []VaccineRecord  `cbor:"v" json:"v"`
	TestRecords     []TestRecord     `cbor:"t" json:"t"`
	RecoveryRecords []RecoveryRecord `cbor:"r" json:"r"`
}

type Name struct {
	FamilyName    string `cbor:"fn" json:"fn"`
	FamilyNameStd string `cbor:"fnt" json:"fnt"`
	GivenName     string `cbor:"gn" json:"gn"`
	GivenNameStd  string `cbor:"gnt" json:"gnt"`
}

// see https://github.com/ehn-dcc-development/ehn-dcc-schema/blob/release/1.3.0/valuesets/disease-agent-targeted.json
type DiseaseTargeted string

func (tg *DiseaseTargeted) UnmarshalCBOR(data []byte) error {
	var id string
	if err := cbor.Unmarshal(data, &id); err != nil {
		return err
	}
	if id == "840539006" {
		*tg = "COVID-19"
	} else {
		*tg = DiseaseTargeted("Unknown test target value: " + id)
	}
	return nil
}

// see https://github.com/ehn-dcc-development/ehn-dcc-schema/blob/release/1.3.0/valuesets/test-type.json
type TestType string

func (tt *TestType) UnmarshalCBOR(data []byte) error {
	var id string
	if err := cbor.Unmarshal(data, &id); err != nil {
		return err
	}
	if id == "LP6464-4" {
		*tt = "Nucleic acid amplification with probe detection"
	} else if id == "LP217198-3" {
		*tt = "Rapid immunoassay"
	} else {
		*tt = TestType("Unknown test type value: " + id)
	}
	return nil
}

// see https://github.com/ehn-dcc-development/ehn-dcc-schema/blob/release/1.3.0/valuesets/test-result.json
type TestResult string

func (tr *TestResult) UnmarshalCBOR(data []byte) error {
	var id string
	if err := cbor.Unmarshal(data, &id); err != nil {
		return err
	}
	if id == "260415000" {
		*tr = "Not detected"
	} else if id == "260373001" {
		*tr = "Detected"
	} else {
		*tr = TestResult("Unknown test result value: " + id)
	}
	return nil
}

// see https://github.com/ehn-dcc-development/ehn-dcc-schema/blob/release/1.3.0/DCC.Types.schema.json
type VaccineRecord struct {
	Target        DiseaseTargeted `cbor:"tg" json:"tg"`
	Vaccine       string          `cbor:"vp" json:"vp"`
	Product       string          `cbor:"mp" json:"mp"`
	Manufacturer  string          `cbor:"ma" json:"ma"`
	Doses         float64         `cbor:"dn" json:"dn"` // int per the spec, but float64 e.g. in IE
	DoseSeries    float64         `cbor:"sd" json:"sd"` // int per the spec, but float64 e.g. in IE
	Date          string          `cbor:"dt" json:"dt"`
	Country       string          `cbor:"co" json:"co"`
	Issuer        string          `cbor:"is" json:"is"`
	CertificateID string          `cbor:"ci" json:"ci"`
}

type TestRecord struct {
	Target   DiseaseTargeted `cbor:"tg" json:"tg"`
	TestType TestType        `cbor:"tt" json:"tt"`

	// Name is the NAA Test Name
	Name string `cbor:"nm" json:"nm"`

	// Manufacturer is the RAT Test name and manufacturer.
	Manufacturer   string     `cbor:"ma" json:"ma"`
	SampleDatetime time.Time  `cbor:"sc" json:"sc"`
	TestResult     TestResult `cbor:"tr" json:"tr"`
	TestingCentre  string     `cbor:"tc" json:"tc"`
	// Country of Test
	Country       string `cbor:"co" json:"co"`
	Issuer        string `cbor:"is" json:"is"`
	CertificateID string `cbor:"ci" json:"ci"`
}

type RecoveryRecord struct {
	Target DiseaseTargeted `cbor:"tg" json:"tg"`

	//     "fr": {
	//       "description": "ISO 8601 complete date of first positive NAA test result",
	//       "type": "string",
	//       "format": "date"
	//     },

	// Country of Test
	Country string `cbor:"co" json:"co"`

	Issuer string `cbor:"is" json:"is"`

	//     "df": {
	//       "description": "ISO 8601 complete date: Certificate Valid From",
	//       "type": "string",
	//       "format": "date"
	//     },
	//     "du": {
	//       "description": "ISO 8601 complete date: Certificate Valid Until",
	//       "type": "string",
	//       "format": "date"
	//     },

	CertificateID string `cbor:"ci" json:"ci"`
}

func calculateKid(encodedCert []byte) []byte {
	result := make([]byte, 8)
	h := sha256.New()
	h.Write(encodedCert)
	sum := h.Sum(nil)
	copy(result, sum)
	return result
}

func unprefix(prefixObject string) (string, error) {
	if !strings.HasPrefix(prefixObject, "HC1:") {
		return "", errors.New("data does not start with HC1: prefix")
	}

	return strings.TrimPrefix(prefixObject, "HC1:"), nil
}

func base45decode(encoded string) ([]byte, error) {
	return eubase45.EUBase45Decode([]byte(encoded))
}

func decompress(compressed []byte) ([]byte, error) {
	zr, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, zr); err != nil {
		return nil, err
	}
	if err := zr.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

type coseHeader struct {
	// Cryptographic algorithm. See COSE Algorithms Registry:
	// https://www.iana.org/assignments/cose/cose.xhtml
	Alg int `cbor:"1,keyasint,omitempty"`
	// Key identifier
	Kid []byte `cbor:"4,keyasint,omitempty"`
	// Full Initialization Vector
	IV []byte `cbor:"5,keyasint,omitempty"`
}

type signedCWT struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected map[interface{}]interface{}
	Payload     []byte
	Signature   []byte
}

type unverifiedCOSE struct {
	v      signedCWT
	p      coseHeader
	claims claims
	cert   *x509.Certificate // set after verification
}

// PublicKeyProvider is typically implemented using a JSON Web Key Set, or by
// pinning a specific government certificate.
type PublicKeyProvider interface {
	// GetPublicKey returns the public key of the certificate for the specified
	// key identifier (or country), or an error if the public key was not found.
	//
	// Country is a ISO 3166 alpha-2 code, e.g. CH.
	//
	// kid are the first 8 bytes of the SHA256 digest of the certificate in DER
	// encoding.
	GetPublicKey(country string, kid []byte) (crypto.PublicKey, error)
}

// CertificateProvider is typically implemented using a JSON Web Key Set, or by
// pinning a specific government certificate.
type CertificateProvider interface {
	// GetCertificate returns the public key of the certificate for the
	// specified country and key identifier, or an error if the certificate was
	// not found.
	//
	// Country is a ISO 3166 alpha-2 code, e.g. CH.
	//
	// kid are the first 8 bytes of the SHA256 digest of the certificate in DER
	// encoding.
	GetCertificate(country string, kid []byte) (*x509.Certificate, error)
}

func (u *unverifiedCOSE) verify(expired func(time.Time) bool, certprov PublicKeyProvider) error {
	kid := u.p.Kid // protected header
	if len(kid) == 0 {
		// fall back to kid (4) from unprotected header
		if b, ok := u.v.Unprotected[uint64(4)]; ok {
			kid = b.([]byte)
		}
	}

	alg := u.p.Alg // protected header
	if alg == 0 {
		// fall back to alg (4) from unprotected header
		if b, ok := u.v.Unprotected[uint64(1)]; ok {
			alg = int(b.(int64))
		}
	}

	const country = "CH" // TODO: use country from claims
	pubKey, err := certprov.GetPublicKey(country, kid)
	if err != nil {
		return err
	}

	if certprov, ok := certprov.(CertificateProvider); ok {
		cert, err := certprov.GetCertificate(country, kid)
		if err != nil {
			return err
		}
		u.cert = cert
	}

	verifier := &cose.Verifier{
		PublicKey: pubKey,
	}

	// COSE algorithm parameter ES256
	// https://datatracker.ietf.org/doc/draft-ietf-cose-rfc8152bis-algs/12/
	if alg == -37 {
		verifier.Alg = cose.PS256
	} else if alg == -7 {
		verifier.Alg = cose.ES256
	} else {
		return fmt.Errorf("unknown alg: %d", alg)
	}

	// We need to use custom verification code instead of the existing Go COSE
	// packages:
	//
	// - go.mozilla.org/cose lacks sign1 support
	//
	// - github.com/veraison/go-cose is a fork which adds sign1 support, but
	//   re-encodes protected headers during signature verification, which does
	//   not pass e.g. dgc-testdata/common/2DCode/raw/CO1.json
	toBeSigned, err := sigStructure(u.v.Protected, u.v.Payload)
	if err != nil {
		return err
	}

	digest, err := hashSigStructure(toBeSigned, verifier.Alg.HashFunc)
	if err != nil {
		return err
	}

	if err := verifier.Verify(digest, u.v.Signature); err != nil {
		return err
	}

	expiration := time.Unix(u.claims.Exp, 0)
	if expired(expiration) {
		return fmt.Errorf("certificate has expired")
	}

	return nil
}

func (u *unverifiedCOSE) decoded() *Decoded {
	return &Decoded{
		Cert:       u.claims.HCert.DCC,
		SignedBy:   u.cert,
		IssuedAt:   time.Unix(u.claims.Iat, 0),
		Expiration: time.Unix(u.claims.Exp, 0),
	}
}

type hcert struct {
	DCC CovidCert `cbor:"1,keyasint"`
}

type claims struct {
	Iss   string `cbor:"1,keyasint"`
	Sub   string `cbor:"2,keyasint"`
	Aud   string `cbor:"3,keyasint"`
	Exp   int64  `cbor:"4,keyasint"`
	Nbf   int    `cbor:"5,keyasint"`
	Iat   int64  `cbor:"6,keyasint"`
	Cti   []byte `cbor:"7,keyasint"`
	HCert hcert  `cbor:"-260,keyasint"`
}

func decodeCOSE(coseData []byte) (*unverifiedCOSE, error) {
	var v signedCWT
	if err := cbor.Unmarshal(coseData, &v); err != nil {
		return nil, fmt.Errorf("cbor.Unmarshal: %v", err)
	}

	var p coseHeader
	if len(v.Protected) > 0 {
		if err := cbor.Unmarshal(v.Protected, &p); err != nil {
			return nil, fmt.Errorf("cbor.Unmarshal(v.Protected): %v", err)
		}
	}

	var c claims
	if err := cbor.Unmarshal(v.Payload, &c); err != nil {
		return nil, fmt.Errorf("cbor.Unmarshal(v.Payload): %v", err)
	}

	return &unverifiedCOSE{
		v:      v,
		p:      p,
		claims: c,
	}, nil
}

// Unverified is a EU Digital COVID Certificate (EUDCC) that was decoded, but
// not yet verified.
type Unverified struct {
	u       *unverifiedCOSE
	decoder *Decoder
}

// SkipVerification skips all cryptographic signature verification and returns
// the unverified certificate data.
func (u *Unverified) SkipVerification() *Decoded {
	return u.u.decoded()
}

// Verify checks the cryptographic signature and returns the verified EU Digital
// COVID Certificate (EUDCC) or an error if verification fails.
//
// certprov can optionally implement the CertificateProvider interface.
func (u *Unverified) Verify(certprov PublicKeyProvider) (*Decoded, error) {
	expired := u.decoder.Expired
	if expired == nil {
		expired = func(expiration time.Time) bool {
			return time.Now().After(expiration)
		}
	}
	if err := u.u.verify(expired, certprov); err != nil {
		return nil, err
	}

	return u.u.decoded(), nil
}

// Decoder is a EU Digital COVID Certificate (EUDCC) decoder.
type Decoder struct {
	Expired func(time.Time) bool
}

// Decode decodes the specified EU Digital COVID Certificate (EUDCC) QR code
// data.
func (d *Decoder) Decode(qrdata string) (*Unverified, error) {
	unprefixed, err := unprefix(qrdata)
	if err != nil {
		return nil, err
	}

	compressed, err := base45decode(unprefixed)
	if err != nil {
		return nil, err
	}

	coseData, err := decompress(compressed)
	if err != nil {
		return nil, err
	}

	unverified, err := decodeCOSE(coseData)
	if err != nil {
		return nil, err
	}

	return &Unverified{
		decoder: d,
		u:       unverified,
	}, nil
}

// DefaultDecoder is a ready-to-use Decoder.
var DefaultDecoder = &Decoder{}

// Decode decodes the specified EU Digital COVID Certificate (EUDCC) QR code
// data.
func Decode(qrdata string) (*Unverified, error) {
	return DefaultDecoder.Decode(qrdata)
}
