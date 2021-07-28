package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/davecgh/go-spew/spew"
	"github.com/stapelberg/coronaqr"
	"github.com/stapelberg/coronaqr/trustlist/trustlistmirror"
)

func printCertificate(decoded *coronaqr.Decoded) {
	fmt.Printf("\n")
	fmt.Printf("COVID certificate:\n")
	fmt.Printf("Issued:     %v\n", decoded.IssuedAt)
	fmt.Printf("Expiration: %v\n", decoded.Expiration)
	fmt.Printf("Contents:   ")
	spew.Dump(decoded.Cert)
}

func main() {
	var (
		verify    = flag.Bool("verify", false, "verify the signature in addition to decoding")
		trustlist = flag.String("trustlist",
			"trustlistmirror/de",
			"Trustlist to obtain certificates from. One of trustlistmirror/de, trustlistmirror/at or trustlistmirror/fr")
	)
	flag.Parse()
	code, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		log.Fatalf("could not read from stdin: %v", err)
	}
	unverified, err := coronaqr.Decode(strings.TrimSpace(string(code)))
	if err != nil {
		log.Fatalf("could not decode certificate QR code: %v", err)
	}
	if !*verify {
		fmt.Printf("Cryptographic signature check skipped (use -verify)\n")
		printCertificate(unverified.SkipVerification())
		return
	}
	list := trustlistmirror.TrustlistDE
	switch strings.ToLower(*trustlist) {
	case "trustlistmirror/de":
		list = trustlistmirror.TrustlistDE
	case "trustlistmirror/at":
		list = trustlistmirror.TrustlistAT
	case "trustlistmirror/fr":
		list = trustlistmirror.TrustlistFR
	case "trustlistmirror/nl":
		list = trustlistmirror.TrustlistNL
	case "trustlistmirror/se":
		list = trustlistmirror.TrustlistSE
	case "trustlistmirror/ch":
		list = trustlistmirror.TrustlistCH
	default:
		log.Fatalf("unknown -trustlist value: %q", *trustlist)
	}
	certProv, err := trustlistmirror.NewCertificateProvider(context.Background(), list)
	if err != nil {
		log.Fatalf("initializing trustlist: %v", err)
	}
	log.Printf("trustlist %q initialized: %v", *trustlist, certProv)
	decoded, err := unverified.Verify(certProv)
	if err != nil {
		log.Fatalf("verification failed: %v", err)
	}
	if cert := decoded.SignedBy; cert == nil {
		fmt.Printf("Cryptographic signature successfully verified\n")
	} else {
		fmt.Printf("Cryptographic signature successfully verified from:\n")
		fmt.Printf("  %v\n", cert.Issuer)
	}

	printCertificate(decoded)
}
