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
		spew.Dump(unverified.SkipVerification())
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
	spew.Dump(decoded)
	fmt.Printf("verification succeeded!\n")
}
