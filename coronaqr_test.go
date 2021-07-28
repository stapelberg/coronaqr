package coronaqr

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func chFromFile(fn string) (*x509.Certificate, []byte, error) {
	b, err := ioutil.ReadFile(fn)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(b)
	if err != nil {
		return nil, nil, err
	}
	return cert, calculateKid(b), nil
}

// “RAW Data File” as per
// https://github.com/eu-digital-green-certificates/dgc-testdata
type rawTestdata struct {
	JSON       CovidCert `json:"JSON"`
	CBOR       string    `json:"CBOR"`
	COSE       string    `json:"COSE"`
	Compressed string    `json:"COMPRESSED"`
	Base45     string    `json:"BASE45"`
	Prefix     string    `json:"PREFIX"`
	TwoDCode   string    `json:"2DCODE"`
	Testctx    struct {
		Version         int      `json:"VERSION"`
		Schema          string   `json:"SCHEMA"`
		Certificate     string   `json:"CERTIFICATE"` // base64-encoded
		ValidationClock string   `json:"VALIDATIONCLOCK"`
		Description     string   `json:"DESCRIPTION"`
		GatewayEnv      []string `json:"GATEWAY-ENV"`
	} `json:"TESTCTX"`
	ExpectedResults struct {
		ValidObject      *bool `json:"EXPECTEDVALIDOBJECT"`
		SchemaValidation *bool `json:"EXPECTEDSCHEMAVALIDATION"`
		Encode           *bool `json:"EXPECTEDENCODE"`
		Decode           *bool `json:"EXPECTEDDECODE"`
		Verify           *bool `json:"EXPECTEDVERIFY"`
		Compression      *bool `json:"EXPECTEDCOMPRESSION"`
		KeyUsage         *bool `json:"EXPECTEDKEYUSAGE"`
		Unprefix         *bool `json:"EXPECTEDUNPREFIX"`
		ValidJSON        *bool `json:"EXPECTEDVALIDJSON"`
		B45Decode        *bool `json:"EXPECTEDB45DECODE"`
		PictureDecode    *bool `json:"EXPECTEDPICTUREDECODE"`
		ExpirationCheck  *bool `json:"EXPECTEDEXPIRATIONCHECK"`
	} `json:"EXPECTEDRESULTS"`
}

func (r *rawTestdata) ExpiredFunc() func(time.Time) bool {
	now, err := time.Parse(time.RFC3339, r.Testctx.ValidationClock)
	if err != nil {
		panic(err)
	}
	return func(expiration time.Time) bool {
		return now.After(expiration)
	}
}

func testInteropDecode(t *testing.T, tt rawTestdata) {
	if tt.ExpectedResults.Decode == nil {
		return // test missing
	}

	certB, err := base64.StdEncoding.DecodeString(tt.Testctx.Certificate)
	if err != nil {
		t.Fatal(err)
	}

	kid := calculateKid(certB)

	cert, err := x509.ParseCertificate(certB)
	if err != nil {
		t.Fatal(err)
	}

	d := &Decoder{Expired: tt.ExpiredFunc()}
	unverified, err := d.Decode(tt.Prefix)
	if !*tt.ExpectedResults.Decode && err == nil {
		t.Fatalf("Decode unexpectedly did not fail")
	}
	if !*tt.ExpectedResults.Decode && err != nil {
		return // decoding failed as expected
	}
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := unverified.Verify(&singleCertificateProvider{
		cert: cert,
		kid:  kid,
	})
	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(tt.JSON, decoded.Cert); diff != "" {
		t.Errorf("Decode: unexpected diff: (-want +got):\n%s", diff)
	}
}

func testInteropUnprefix(t *testing.T, tt rawTestdata) {
	if tt.ExpectedResults.Unprefix == nil {
		return // test missing
	}
	base45, err := unprefix(tt.Prefix)
	if !*tt.ExpectedResults.Unprefix && err == nil {
		t.Fatalf("unprefix unexpectedly did not fail")
	}
	if !*tt.ExpectedResults.Unprefix && err != nil {
		return // unprefix failed as expected
	}
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(tt.Base45, base45); diff != "" {
		t.Errorf("unprefix: unexpected diff: (-want +got):\n%s", diff)
	}
}

func testInteropB45Decode(t *testing.T, tt rawTestdata) {
	if tt.ExpectedResults.B45Decode == nil {
		return // test missing
	}
	decoded, err := base45decode(tt.Base45)
	if !*tt.ExpectedResults.B45Decode && err == nil {
		t.Fatalf("base45decode unexpectedly did not fail")
	}
	if !*tt.ExpectedResults.B45Decode && err != nil {
		return // decoding failed as expected
	}
	if err != nil {
		t.Fatal(err)
	}
	got := decoded
	var want []byte
	if tt.Compressed != "" {
		var err error
		want, err = hex.DecodeString(tt.Compressed)
		if err != nil {
			t.Fatal(err)
		}
	} else {
		decompressed, err := decompress(decoded)
		if err != nil {
			t.Fatal(err)
		}
		got = decompressed

		want, err = hex.DecodeString(tt.COSE)
		if err != nil {
			t.Fatal(err)
		}
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("base45decode: unexpected diff: (-want +got):\n%s", diff)
	}
}

func testInteropDecompress(t *testing.T, tt rawTestdata) {
	if tt.ExpectedResults.Compression == nil {
		return // test missing
	}
	compressed, err := hex.DecodeString(tt.Compressed)
	if err != nil {
		t.Fatal(err)
	}

	decompressed, err := decompress(compressed)
	if !*tt.ExpectedResults.Compression && err == nil {
		t.Fatalf("decompress unexpectedly did not fail")
	}
	if !*tt.ExpectedResults.Compression && err != nil {
		return // decompress failed as expected
	}
	if err != nil {
		t.Fatal(err)
	}

	want, err := hex.DecodeString(tt.COSE)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(want, decompressed); diff != "" {
		t.Errorf("decompress: unexpected diff: (-want +got):\n%s", diff)
	}
}

type singleCertificateProvider struct {
	cert *x509.Certificate
	kid  []byte
}

func (p *singleCertificateProvider) GetPublicKey(country string, kid []byte) (crypto.PublicKey, error) {
	if !bytes.Equal(p.kid, kid) {
		return nil, fmt.Errorf("no such certificate (%s, %x): got %x", country, kid, p.kid)
	}
	return p.cert.PublicKey, nil
}

func (p *singleCertificateProvider) GetCertificate(country string, kid []byte) (*x509.Certificate, error) {
	if !bytes.Equal(p.kid, kid) {
		return nil, fmt.Errorf("no such certificate (%s, %x): got %x", country, kid, p.kid)
	}
	return p.cert, nil
}

func testInteropVerify(t *testing.T, tt rawTestdata) {
	if tt.ExpectedResults.Verify == nil {
		return // test missing
	}
	cose, err := hex.DecodeString(tt.COSE)
	if err != nil {
		t.Fatal(err)
	}

	unverified, err := decodeCOSE(cose)
	if !*tt.ExpectedResults.Verify && err != nil {
		return // verify failed as expected
	}
	if err != nil {
		t.Fatalf("decodeCOSE(%x): %v", cose, err)
	}

	certB, err := base64.StdEncoding.DecodeString(tt.Testctx.Certificate)
	if err != nil {
		t.Fatal(err)
	}

	kid := calculateKid(certB)

	cert, err := x509.ParseCertificate(certB)
	if err != nil {
		t.Fatal(err)
	}

	err = unverified.verify(tt.ExpiredFunc(), &singleCertificateProvider{
		cert: cert,
		kid:  kid,
	})
	if !*tt.ExpectedResults.Verify && err == nil {
		t.Fatalf("Verify unexpectedly did not fail")
	}
	if !*tt.ExpectedResults.Verify && err != nil {
		return // verify failed as expected
	}
	if err != nil {
		t.Errorf("Verify: %v", err)
	}

}

func testInteropExpectations(t *testing.T, tt rawTestdata) {
	//spew.Dump(tt)
	// TODO: we should check for each of these bools if they were unset (test
	// should not run), false (test should fail) or true (test should succeed).

	// 1. Load the picture and extract the prefixed BASE45content
	// testInteropPictureDecode(t, tt)

	// 2. Load Prefix Object from RAW Content and remove the prefix. Validate
	// against the BASE45 raw content.
	testInteropUnprefix(t, tt)

	// TODO: this is wrong, should be compared against COMPRESSED for now?
	// 3. Decode the BASE45 RAW Content and validate the COSE content against
	// the RAW content.
	testInteropB45Decode(t, tt)

	// 9. The value given in COMPRESSED has to be decompressed by zlib and must
	// match to the value given in COSE.
	testInteropDecompress(t, tt)

	// 4. Check the EXP Field for expiring against the VALIDATIONCLOCK time.
	// TODO: which field is meant here?

	// 5. Verify the signature of the COSE Object against the JWK Public Key.
	testInteropVerify(t, tt)

	// TODO: 6, 8

	// 7. Transform CBOR into JSON and validate against the RAW JSON content.
	testInteropDecode(t, tt)
}

func TestInterop(t *testing.T) {
	for _, country := range []string{"CH", "RO", "HR", "LU", "common"} {
		matches, err := filepath.Glob("testdata/dgc-testdata/" + country + "/2DCode/raw/*.json")
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range matches {
			t.Run(match, func(t *testing.T) {
				b, err := ioutil.ReadFile(match)
				if err != nil {
					t.Fatalf("ReadFile(%s): %v", match, err)
				}
				var tt rawTestdata
				if err := json.Unmarshal(b, &tt); err != nil {
					t.Fatalf("Unmarshal: %v", err)
				}
				testInteropExpectations(t, tt)
			})
		}
	}
}

type singlePubkeyProvider struct {
	pubKey crypto.PublicKey
	kid    []byte
}

func (p *singlePubkeyProvider) GetPublicKey(country string, kid []byte) (crypto.PublicKey, error) {
	if !bytes.Equal(p.kid, kid) {
		return nil, fmt.Errorf("no such certificate (%s, %x): got %x", country, kid, p.kid)
	}
	return p.pubKey, nil
}

func TestLight(t *testing.T) {
	// From https://github.com/admin-ch/CovidCertificate-SDK-Kotlin/blob/883f4b40b4a617485e3527d8dbe833070c6440b5/src/test/java/ch/admin/bag/covidcertificate/sdk/core/TestData.kt#L18
	const lt1a = `LT1:6BFU90V10RDWT 9O60GO0000W50JB06H08CK34C/70YM8N34GB8WY0ABC VI597.FKMTKGVC*JC1A6/Q63W5KF6746TPCBEC7ZKW.CU2DNXO VD5$C JC3/DMP8$ILZEDZ CW.C9WE.Y9AY8+S9VIAI3D8WEVM8:S9C+9$PC5$CUZCY$5Y$527BJZH/HULXS+Q5M8R .S6YE2JCU.OR8ICBM+2QZFLK DHPHCS3Q6EK3A:RFH%HGEV:DE79K/8NM7MY.9VRKV5SP89HN2OED85SW.C8A9`

	dec := &Decoder{
		// The lt1a test data does not have an expiration date o_O.
		Expired: func(time.Time) bool { return false },
	}
	unverified, err := dec.Decode(lt1a)
	if err != nil {
		t.Fatal(err)
	}

	// https://github.com/admin-ch/CovidCertificate-SDK-Kotlin/blob/883f4b40b4a617485e3527d8dbe833070c6440b5/src/test/java/ch/admin/bag/covidcertificate/sdk/core/TestData.kt#L56
	kid, err := base64.StdEncoding.DecodeString("AAABAQICAwM=")
	if err != nil {
		t.Fatal(err)
	}
	curve := elliptic.P256()
	x := new(big.Int)
	y := new(big.Int)
	// https://github.com/admin-ch/CovidCertificate-SDK-Kotlin/blob/883f4b40b4a617485e3527d8dbe833070c6440b5/src/test/java/ch/admin/bag/covidcertificate/sdk/core/TestData.kt#L57
	decX, err := base64.StdEncoding.DecodeString("ceBrQgj3RwWzoxkv8/vApqkB7yJGfpBC9TjeIiXUR0U=")
	if err != nil {
		t.Fatal(err)
	}
	x.SetBytes(decX)
	// https://github.com/admin-ch/CovidCertificate-SDK-Kotlin/blob/883f4b40b4a617485e3527d8dbe833070c6440b5/src/test/java/ch/admin/bag/covidcertificate/sdk/core/TestData.kt#L58
	decY, err := base64.StdEncoding.DecodeString("g9ufnhfjFLVIiQYeQWmQATN/CMiVbfAgFp/08+Qqv2s=")
	if err != nil {
		t.Fatal(err)
	}
	y.SetBytes(decY)
	pubKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}
	decoded, err := unverified.Verify(&singlePubkeyProvider{
		pubKey: pubKey,
		kid:    kid,
	})
	if err != nil {
		t.Fatal(err)
	}
	got := decoded.Cert
	want := CovidCert{
		Version: "1.0.0",
		PersonalName: Name{
			FamilyName:    "Müller",
			FamilyNameStd: "MUELLER",
			GivenName:     "Céline",
			GivenNameStd:  "CELINE",
		},
		DateOfBirth: "1943-02-01",
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("unexpected Decode() output: diff (-want +got):\n%s", diff)
	}
}
