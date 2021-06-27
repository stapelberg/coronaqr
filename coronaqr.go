// Package coronaqr provides a decoder for EU Digital COVID Certificate (EUDCC)
// QR code data.
//
// See https://github.com/eu-digital-green-certificates for the specs, testdata,
// etc.
package coronaqr

import (
	"bytes"
	"compress/zlib"
	"errors"
	"io"
	"strings"

	"github.com/fxamacker/cbor"
	"github.com/minvws/base45-go/eubase45"
)

// Decoded represents a decoded EU Digital COVID Certificate (EUDCC).
type Decoded struct {
	Cert CovidCert

	// TODO: Include metadata, e.g. certificate timestamp and expiration.
}

type CovidCert struct {
	Version        string          `cbor:"ver"`
	PersonalName   Name            `cbor:"nam"`
	DateOfBirth    string          `cbor:"dob"`
	VaccineRecords []VaccineRecord `cbor:"v"`
}

type Name struct {
	FamilyName    string `cbor:"fn"`
	FamilyNameStd string `cbor:"fnt"`
	GivenName     string `cbor:"gn"`
	GivenNameStd  string `cbor:"gnt"`
}

type VaccineRecord struct {
	Target        string `cbor:"tg"`
	Vaccine       string `cbor:"vp"`
	Product       string `cbor:"mp"`
	Manufacturer  string `cbor:"ma"`
	Doses         int    `cbor:"dn"`
	DoseSeries    int    `cbor:"sd"`
	Date          string `cbor:"dt"`
	Country       string `cbor:"co"`
	Issuer        string `cbor:"is"`
	CertificateID string `cbor:"ci"`
}

// Decode decodes (but does not verify any signatures!) the specified EU Digital
// COVID Certificate (EUDCC) QR code data.
func Decode(qrdata string) (*Decoded, error) {
	if !strings.HasPrefix(qrdata, "HC1:") {
		return nil, errors.New("data does not start with HC1: prefix")
	}

	decoded, err := eubase45.EUBase45Decode([]byte(strings.TrimPrefix(qrdata, "HC1:")))
	if err != nil {
		return nil, err
	}

	zr, err := zlib.NewReader(bytes.NewReader(decoded))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	var cborBuf bytes.Buffer
	if _, err := io.Copy(&cborBuf, zr); err != nil {
		return nil, err
	}
	if err := zr.Close(); err != nil {
		return nil, err
	}

	type coseHeader struct {
		Alg int    `cbor:"1,keyasint,omitempty"`
		Kid []byte `cbor:"4,keyasint,omitempty"`
		IV  []byte `cbor:"5,keyasint,omitempty"`
	}
	type signedCWT struct {
		_           struct{} `cbor:",toarray"`
		Protected   []byte
		Unprotected coseHeader
		Payload     []byte
		Signature   []byte
	}
	var v signedCWT
	if err := cbor.Unmarshal(cborBuf.Bytes(), &v); err != nil {
		return nil, err
	}

	// TODO: verify signature, add knob to skip the check (decode only)

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
	var c claims
	if err := cbor.Unmarshal(v.Payload, &c); err != nil {
		return nil, err
	}

	return &Decoded{Cert: c.HCert.DCC}, nil
}
