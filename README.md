# Go Corona QR Code Decoder

[![Go Reference](https://pkg.go.dev/badge/github.com/stapelberg/coronaqr.svg)](https://pkg.go.dev/github.com/stapelberg/coronaqr)

This repository contains a decoder for EU Digital COVID Certificate (EUDCC) QR
code data, written in Go.

If you got vaccinated and want to know what is stored in the QR code, this
package (and example program) can answer that question!

Example usage:
```
go install github.com/stapelberg/coronaqr/cmd/coronadecode@latest

apt install curl zbar-tools
curl -sL https://github.com/eu-digital-green-certificates/dgc-testdata/raw/main/CH/png/1.png | \
	zbarimg --quiet --raw - | \
	coronadecode
```

(With older Go versions before 1.16, use `go get -u github.com/stapelberg/coronaqr/cmd/coronadecode` instead.)
