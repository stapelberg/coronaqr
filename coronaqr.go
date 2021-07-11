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
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/minvws/base45-go/eubase45"
	"github.com/veraison/go-cose"
)

// Decoded is a EU Digital COVID Certificate (EUDCC) that has been decoded and
// possibly verified.
type Decoded struct {
	Cert CovidCert

	// TODO: Include metadata, e.g. certificate timestamp and expiration.
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

// see https://github.com/ehn-dcc-development/ehn-dcc-schema/blob/release/1.3.0/DCC.Types.schema.json
type VaccineRecord struct {
	Target        string `cbor:"tg" json:"tg"`
	Vaccine       string `cbor:"vp" json:"vp"`
	Product       string `cbor:"mp" json:"mp"`
	Manufacturer  string `cbor:"ma" json:"ma"`
	Doses         int    `cbor:"dn" json:"dn"`
	DoseSeries    int    `cbor:"sd" json:"sd"`
	Date          string `cbor:"dt" json:"dt"`
	Country       string `cbor:"co" json:"co"`
	Issuer        string `cbor:"is" json:"is"`
	CertificateID string `cbor:"ci" json:"ci"`
}

type TestRecord struct {
	Target string `cbor:"tg" json:"tg"`
	// "tt": {
	//   "description": "Type of Test",
	//   "$ref": "https://id.uvci.eu/DCC.ValueSets.schema.json#/$defs/test-type"
	// },

	// Name is the NAA Test Name
	Name string `cbor:"nm" json:"nm"`

	// Manufacturer is the RAT Test name and manufacturer.
	Manufacturer string `cbor:"ma" json:"ma"`
	// "sc": {
	//   "description": "Date/Time of Sample Collection",
	//   "type": "string",
	//   "format": "date-time"
	// },
	// "tr": {
	//   "description": "Test Result",
	//   "$ref": "https://id.uvci.eu/DCC.ValueSets.schema.json#/$defs/test-result"
	// },
	TestingCentre string `cbor:"tc" json:"tc"`
	// Country of Test
	Country       string `cbor:"co" json:"co"`
	Issuer        string `cbor:"is" json:"is"`
	CertificateID string `cbor:"ci" json:"ci"`
}

type RecoveryRecord struct {
	Target string `cbor:"tg" json:"tg"`

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

func unprefix(prefixObject string) string {
	return strings.TrimPrefix(prefixObject, "HC1:")
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
	GetCertificate(country string, kid []byte) (crypto.PublicKey, error)
}

func (u *unverifiedCOSE) Verify(certprov CertificateProvider) error {
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
	cert, err := certprov.GetCertificate(country, kid)
	if err != nil {
		return err
	}

	verifier := &cose.Verifier{
		PublicKey: cert,
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

	// TODO: check expiration timestamp, too

	return nil
}

type hcert struct {
	DCC CovidCert `cbor:"1,keyasint"`
}

type claims struct {
	Iss   string `cbor:"1,keyasint"`
	Sub   string `cbor:"2,keyasint"`
	Aud   string `cbor:"3,keyasint"`
	Exp   int    `cbor:"4,keyasint"`
	Nbf   int    `cbor:"5,keyasint"`
	Iat   int    `cbor:"6,keyasint"`
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
	u *unverifiedCOSE
}

// SkipVerification skips all cryptographic signature verification and returns
// the unverified certificate data.
func (u *Unverified) SkipVerification() *Decoded {
	return &Decoded{Cert: u.u.claims.HCert.DCC}
}

// Verify checks the cryptographic signature and returns the verified EU Digital
// COVID Certificate (EUDCC) or an error if verification fails.
func (u *Unverified) Verify(certprov CertificateProvider) (*Decoded, error) {
	if err := u.u.Verify(certprov); err != nil {
		return nil, err
	}

	// TODO: fill in metadata regarding signature?
	return &Decoded{Cert: u.u.claims.HCert.DCC}, nil
}

// Decode decodes the specified EU Digital COVID Certificate (EUDCC) QR code
// data.
func Decode(qrdata string) (*Unverified, error) {
	if !strings.HasPrefix(qrdata, "HC1:") {
		return nil, errors.New("data does not start with HC1: prefix")
	}

	compressed, err := base45decode(unprefix(qrdata))
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
		u: unverified,
	}, nil

}
