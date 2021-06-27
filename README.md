# Go Corona QR Code Decoder

This repository contains a decoder for EU Digital COVID Certificate (EUDCC) QR
code data, written in Go.

Example usage:
```
go install github.com/stapelberg/coronaqr/cmd/coronadecode@latest
curl -sL https://github.com/eu-digital-green-certificates/dgc-testdata/raw/main/CH/png/1.png | zbarimg --quiet --raw -  | coronadecode
```
