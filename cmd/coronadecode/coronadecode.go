package main

import (
	"io"
	"log"
	"os"
	"strings"

	"github.com/davecgh/go-spew/spew"
	"github.com/stapelberg/coronaqr"
)

func main() {
	code, err := io.ReadAll(os.Stdin)
	if err != nil {
		log.Fatalf("could not read from stdin: %v", err)
	}
	decoded, err := coronaqr.Decode(strings.TrimSpace(string(code)))
	if err != nil {
		log.Fatalf("could not decode certificate QR code: %v", err)
	}
	spew.Dump(decoded)
}
