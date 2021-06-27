# Go Corona QR Code Decoder

This repository contains a decoder for EU Digital COVID Certificate (EUDCC) QR
code data, written in Go.

Example usage:
```
go install github.com/stapelberg/coronaqr/cmd/coronadecode@latest

apt install curl zbar-tools
curl -sL https://github.com/eu-digital-green-certificates/dgc-testdata/raw/main/CH/png/1.png | \
	zbarimg --quiet --raw - | \
	coronadecode
```

(With older Go versions before 1.16, use `go get -u github.com/stapelberg/coronaqr/cmd/coronadecode` instead.)
