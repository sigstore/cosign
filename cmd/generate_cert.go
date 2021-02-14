/*
Copyright The Cosign Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"io/ioutil"
	"log"
	"math/big"
	"time"

	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/projectcosign/cosign/pkg"
)

func GenerateCert() *ffcli.Command {
	var (
		flagset = flag.NewFlagSet("cosign generate-cert", flag.ExitOnError)
		key     = flagset.String("key", "", "path to the private key")
		name    = flagset.String("name", "", "name to include in the cert")
		csr     = flagset.Bool("request", false, "whether to generate a csr")
		ca      = flagset.String("ca", "", "path to ca certificate")
	)

	return &ffcli.Command{
		Name:       "generate-cert",
		ShortUsage: "cosign generate-cert",
		ShortHelp:  "generate-cert generates a cert",
		FlagSet:    flagset,
		Exec: func(ctx context.Context, args []string) error {
			return generateCert(ctx, *key, *name, *ca, *csr)
		},
	}
}

func generateCert(ctx context.Context, keyPath, name, ca string, request bool) error {
	pass, err := getPass(false)
	if err != nil {
		return err
	}
	pk, err := pkg.LoadPrivateKey(keyPath, pass)
	if err != nil {
		return err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
	}

	notBefore := time.Now()

	notAfter := notBefore.Add(7 * time.Hour * 24)

	var derBytes []byte
	var pemType string
	if request {
		template := x509.CertificateRequest{
			EmailAddresses: []string{name},
		}
		derBytes, err = x509.CreateCertificateRequest(rand.Reader, &template, pk)
		pemType = "CERTIFICATE REQUEST"

	} else {
		template := x509.Certificate{
			SerialNumber:   serialNumber,
			EmailAddresses: []string{name},
			NotBefore:      notBefore,
			NotAfter:       notAfter,

			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			BasicConstraintsValid: true,
		}
		var parent = &template
		if ca != "" {
			pemBytes, err := ioutil.ReadFile(ca)
			if err != nil {
				return err
			}
			asn1Bytes, _ := pem.Decode(pemBytes)
			parent, err = x509.ParseCertificate(asn1Bytes.Bytes)
			if err != nil {
				return err
			}
		}
		derBytes, err = x509.CreateCertificate(rand.Reader, &template, parent, pk.Public(), pk)
		pemType = "CERTIFICATE"

	}
	if err != nil {
		return err
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Bytes: derBytes,
		Type:  pemType,
	})

	if err := ioutil.WriteFile("cosign.pem", pemBytes, 0600); err != nil {
		return err
	}
	return nil
}
