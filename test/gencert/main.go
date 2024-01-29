// Copyright 2023 The Sigstore Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// code is based on the snippet https://gist.github.com/shaneutt/5e1995295cff6721c89a71d13a71c251
// with a permissive (Public Domain) License.

// TODO(dmitris) - refactor to move the code generating certificates and writing to files
// to a separate function.

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

func main() {
	var genIntermediate = flag.Bool("intermediate", false, "generate intermediate CA")
	var outputSuffix = flag.String("output-suffix", "", "suffix to append to generated files before the extension")
	flag.Parse()

	// set up our CA certificate
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:       []string{"CA Company, INC."},
			OrganizationalUnit: []string{"CA Root Team"},
			Country:            []string{"US"},
			Province:           []string{""},
			Locality:           []string{"San Francisco"},
			StreetAddress:      []string{"Golden Gate Bridge"},
			PostalCode:         []string{"94016"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning /*, x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth */},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		EmailAddresses:        []string{"ca@example.com"},
	}

	// create our private and public key
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatal(err)
	}

	// create the CA
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		log.Fatal(err)
	}

	// pem encode
	fname := "ca-root" + *outputSuffix + ".pem"
	caCertFile, err := os.OpenFile(fname, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		log.Fatalf("unable to write to %s: %v", fname, err)
	}
	err = pem.Encode(caCertFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	if err != nil {
		log.Fatalf("unable to write to %s: %v", fname, err)
	}
	fname = "ca-key" + *outputSuffix + ".pem"
	caPrivKeyFile, err := os.OpenFile(fname, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0400)
	if err != nil {
		log.Fatal(err)
	}
	defer caPrivKeyFile.Close()
	err = pem.Encode(caPrivKeyFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})
	if err != nil {
		log.Fatalf("unable to create to %s: %v", fname, err) //nolint:gocritic
	}

	// generate intermediate CA if requested
	var caIntermediate *x509.Certificate
	var caIntermediatePrivKey *rsa.PrivateKey
	if *genIntermediate {
		caIntermediate = &x509.Certificate{
			SerialNumber: big.NewInt(2019),
			Subject: pkix.Name{
				Organization:       []string{"CA Company, INC."},
				OrganizationalUnit: []string{"CA Intermediate Team"},
				Country:            []string{"US"},
				Province:           []string{""},
				Locality:           []string{"San Francisco"},
				StreetAddress:      []string{"Golden Gate Bridge"},
				PostalCode:         []string{"94016"},
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().AddDate(10, 0, 0),
			IsCA:                  true,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning /*, x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth */},
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
			EmailAddresses:        []string{"ca@example.com"},
		}
		// create our private and public key
		caIntermediatePrivKey, err = rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			log.Fatal(err)
		}

		// create the Intermediate CA
		caIntermediateBytes, err := x509.CreateCertificate(rand.Reader, caIntermediate, ca, &caIntermediatePrivKey.PublicKey, caPrivKey)
		if err != nil {
			log.Fatal(err)
		}

		// pem encode
		fname = "ca-intermediate" + *outputSuffix + ".pem"
		caIntermediateCertFile, err := os.OpenFile(fname, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			log.Fatalf("unable to write to %s: %v", fname, err)
		}
		err = pem.Encode(caIntermediateCertFile, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: caIntermediateBytes,
		})
		if err != nil {
			log.Fatalf("unable to write to %s: %v", fname, err)
		}
		fname = "ca-intermediate-key" + *outputSuffix + ".pem"
		caIntermediatePrivKeyFile, err := os.OpenFile(fname, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0400)
		if err != nil {
			log.Fatal(err)
		}
		defer caIntermediatePrivKeyFile.Close()
		err = pem.Encode(caIntermediatePrivKeyFile, &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(caIntermediatePrivKey),
		})
		if err != nil {
			log.Fatalf("unable to create to %s: %v", fname, err) //nolint:gocritic
		}
	}
	// set up our server certificate
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:       []string{"End User"},
			OrganizationalUnit: []string{"End Node Team"},
			Country:            []string{"US"},
			Province:           []string{""},
			Locality:           []string{"San Francisco"},
			StreetAddress:      []string{"Golden Gate Bridge"},
			PostalCode:         []string{"94016"},
		},
		IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:      time.Now(),
		NotAfter:       time.Now().AddDate(10, 0, 0),
		SubjectKeyId:   []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning /* x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth */},
		KeyUsage:       x509.KeyUsageDigitalSignature,
		EmailAddresses: []string{"xyz@nosuchprovider.com"},
		DNSNames:       []string{"next.hugeunicorn.xyz"},
	}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatal(err)
	}

	var certBytes []byte
	if !*genIntermediate {
		certBytes, err = x509.CreateCertificate(rand.Reader, cert, ca, &certPrivKey.PublicKey, caPrivKey)
	} else {
		certBytes, err = x509.CreateCertificate(rand.Reader, cert, caIntermediate, &caIntermediatePrivKey.PublicKey, caIntermediatePrivKey)
	}
	if err != nil {
		log.Fatal(err)
	}

	fname = "cert" + *outputSuffix + ".pem"
	certFile, err := os.OpenFile(fname, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer certFile.Close()
	err = pem.Encode(certFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err != nil {
		log.Fatalf("failed to encode cert: %v", err)
	}

	fname = "key" + *outputSuffix + ".pem"
	keyFile, err := os.OpenFile(fname, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0400)
	if err != nil {
		log.Fatal(err)
	}
	defer keyFile.Close()
	err = pem.Encode(keyFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})
	if err != nil {
		log.Fatalf("failed to encode private key to %s: %v", fname, err)
	}
}
