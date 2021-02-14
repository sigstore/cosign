package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

var cert = `-----BEGIN CERTIFICATE-----
MIIBFTCByKADAgECAhEAurtRKdM6P8HOKFRPSwpJWTAFBgMrZXAwADAeFw0yMTAy
MTQwMDU1NTFaFw0yMTAyMjEwMDU1NTFaMAAwKjAFBgMrZXADIQCOrTFUlaCgizmY
872DRAdS6t/5gRRL3+W1aOQ7vnufVqNXMFUwDgYDVR0PAQH/BAQDAgbAMBMGA1Ud
JQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAwIAYDVR0RAQH/BBYwFIESbG9y
ZW5jLmRAZ21haWwuY29tMAUGAytlcANBAFtHGyyGh2J6qsT5m3DhilRkdYPgI/WO
iEMw1YC5bygBlI6QBPuGQK67MqPekZRqCKQRiE8+VWo+HzgWaoohIQA=
-----END CERTIFICATE-----
`

func main() {
	pemBlock, _ := pem.Decode([]byte(cert))

	x, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		panic(err)
	}
	fmt.Println(x.Issuer)
}
