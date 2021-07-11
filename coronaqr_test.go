package coronaqr

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
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
		ValidObject      bool `json:"EXPECTEDVALIDOBJECT"`
		SchemaValidation bool `json:"EXPECTEDSCHEMAVALIDATION"`
		Encode           bool `json:"EXPECTEDENCODE"`
		Decode           bool `json:"EXPECTEDDECODE"`
		Verify           bool `json:"EXPECTEDVERIFY"`
		Compression      bool `json:"EXPECTEDCOMPRESSION"`
		KeyUsage         bool `json:"EXPECTEDKEYUSAGE"`
		Unprefix         bool `json:"EXPECTEDUNPREFIX"`
		ValidJSON        bool `json:"EXPECTEDVALIDJSON"`
		B45Decode        bool `json:"EXPECTEDB45DECODE"`
		PictureDecode    bool `json:"EXPECTEDPICTUREDECODE"`
		ExpirationCheck  bool `json:"EXPECTEDEXPIRATIONCHECK"`
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
	if !tt.ExpectedResults.Decode {
		return
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
	if !tt.ExpectedResults.Unprefix {
		return
	}
	base45 := unprefix(tt.Prefix)
	if diff := cmp.Diff(tt.Base45, base45); diff != "" {
		t.Errorf("unprefix: unexpected diff: (-want +got):\n%s", diff)
	}
}

func testInteropB45Decode(t *testing.T, tt rawTestdata) {
	if !tt.ExpectedResults.B45Decode {
		return
	}
	decoded, err := base45decode(tt.Base45)
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
	if !tt.ExpectedResults.Compression {
		return
	}
	compressed, err := hex.DecodeString(tt.Compressed)
	if err != nil {
		t.Fatal(err)
	}

	decompressed, err := decompress(compressed)
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
	if !tt.ExpectedResults.Verify {
		return
	}
	cose, err := hex.DecodeString(tt.COSE)
	if err != nil {
		t.Fatal(err)
	}

	unverified, err := decodeCOSE(cose)
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

	if err := unverified.verify(tt.ExpiredFunc(), &singleCertificateProvider{
		cert: cert,
		kid:  kid,
	}); err != nil {
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
