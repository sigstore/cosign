// Copyright 2024 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"google.golang.org/protobuf/encoding/protojson"
)

var bundlePath *string
var certPath *string
var certOIDC *string
var certSAN *string
var identityToken *string
var signaturePath *string
var trustedRootPath *string

func usage() {
	fmt.Println("Usage:")
	fmt.Printf("\t%s sign --identity-token TOKEN --signature FILE --certificate FILE FILE\n", os.Args[0])
	fmt.Printf("\t%s sign-bundle --identity-token TOKEN --bundle FILE FILE\n", os.Args[0])
	fmt.Printf("\t%s verify --signature FILE --certificate FILE --certificate-identity IDENTITY --certificate-oidc-issuer URL [--trusted-root FILE] FILE\n", os.Args[0])
	fmt.Printf("\t%s verify-bundle --bundle FILE --certificate-identity IDENTITY --certificate-oidc-issuer URL [--trusted-root FILE] FILE\n", os.Args[0])
}

func parseArgs() {
	for i := 2; i < len(os.Args); {
		switch os.Args[i] {
		// TODO: support staging (see https://github.com/sigstore/cosign/issues/2434)
		//
		// Today cosign signing does not yet use sigstore-go, and so we would
		// need to make some clever invocation of `cosign initialize` to
		// support staging. Instead it might make sense to wait for cosign
		// signing to use sigstore-go.
		case "--bundle":
			bundlePath = &os.Args[i+1]
			i += 2
		case "--certificate":
			certPath = &os.Args[i+1]
			i += 2
		case "--certificate-oidc-issuer":
			certOIDC = &os.Args[i+1]
			i += 2
		case "--certificate-identity":
			certSAN = &os.Args[i+1]
			i += 2
		case "--identity-token":
			identityToken = &os.Args[i+1]
			i += 2
		case "--signature":
			signaturePath = &os.Args[i+1]
			i += 2
		case "--trusted-root":
			trustedRootPath = &os.Args[i+1]
			i += 2
		default:
			i++
		}
	}
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	parseArgs()

	args := []string{}

	switch os.Args[1] {
	case "sign":
		args = append(args, "sign-blob")
		if signaturePath != nil {
			args = append(args, "--output-signature", *signaturePath)
		}
		if certPath != nil {
			args = append(args, "--output-certificate", *certPath)
		}
		args = append(args, "-y")

	case "sign-bundle":
		args = append(args, "sign-blob")
		args = append(args, "-y")

	case "verify":
		args = append(args, "verify-blob")

		// TODO: for now, we handle `verify` by constructing a bundle
		// (see https://github.com/sigstore/cosign/issues/3700)
		//
		// Today cosign only supports `--trusted-root` with the new bundle
		// format. When cosign supports `--trusted-root` with detached signed
		// material, we can supply this content with `--certificate`
		// and `--signature` instead.
		fileBytes, err := os.ReadFile(os.Args[len(os.Args)-1])
		if err != nil {
			log.Fatal(err)
		}

		fileDigest := sha256.Sum256(fileBytes)

		pb := protobundle.Bundle{
			MediaType: "application/vnd.dev.sigstore.bundle+json;version=0.1",
		}

		if signaturePath != nil {
			sig, err := os.ReadFile(*signaturePath)
			if err != nil {
				log.Fatal(err)
			}

			sigBytes, err := base64.StdEncoding.DecodeString(string(sig))
			if err != nil {
				log.Fatal(err)
			}

			pb.Content = &protobundle.Bundle_MessageSignature{
				MessageSignature: &protocommon.MessageSignature{
					MessageDigest: &protocommon.HashOutput{
						Algorithm: protocommon.HashAlgorithm_SHA2_256,
						Digest:    fileDigest[:],
					},
					Signature: sigBytes,
				},
			}
		}
		if certPath != nil {
			cert, err := os.ReadFile(*certPath)
			if err != nil {
				log.Fatal(err)
			}

			pemCert, _ := pem.Decode(cert)
			if pemCert == nil {
				log.Fatalf("unable to load cerficate from %s", *certPath)
			}

			signingCert := protocommon.X509Certificate{
				RawBytes: pemCert.Bytes,
			}

			pb.VerificationMaterial = &protobundle.VerificationMaterial{
				Content: &protobundle.VerificationMaterial_X509CertificateChain{
					X509CertificateChain: &protocommon.X509CertificateChain{
						Certificates: []*protocommon.X509Certificate{&signingCert},
					},
				},
			}
		}

		bundleFile, err := os.CreateTemp(os.TempDir(), "bundle.sigstore.json")
		if err != nil {
			log.Fatal(err)
		}
		bundleFileName := bundleFile.Name()
		pbBytes, err := protojson.Marshal(&pb)
		if err != nil {
			log.Fatal(err)
		}
		if err := os.WriteFile(bundleFileName, pbBytes, 0600); err != nil {
			log.Fatal(err)
		}
		bundlePath = &bundleFileName
		args = append(args, "--insecure-ignore-tlog")

	case "verify-bundle":
		args = append(args, "verify-blob")

		// How do we know if we should expect signed timestamps or not?
		// Let's crack open the bundle
		if bundlePath != nil {
			b, err := bundle.LoadJSONFromPath(*bundlePath)
			if err != nil {
				log.Fatal(err)
			}
			ts, err := b.Timestamps()
			if err != nil {
				log.Fatal(err)
			}
			if len(ts) > 0 {
				args = append(args, "--use-signed-timestamps")
			}
		}

	default:
		log.Fatalf("Unsupported command %s", os.Args[1])
	}

	if bundlePath != nil {
		args = append(args, "--bundle", *bundlePath)
		args = append(args, "--new-bundle-format")
	}
	if identityToken != nil {
		args = append(args, "--identity-token", *identityToken)
	}
	if certSAN != nil {
		args = append(args, "--certificate-identity", *certSAN)
	}
	if certOIDC != nil {
		args = append(args, "--certificate-oidc-issuer", *certOIDC)
	}
	if trustedRootPath != nil {
		args = append(args, "--trusted-root", *trustedRootPath)
	}
	args = append(args, os.Args[len(os.Args)-1])

	dir := filepath.Dir(os.Args[0])
	cmd := exec.Command(filepath.Join(dir, "cosign"), args...) // #nosec G204
	var out strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()

	fmt.Println(out.String())

	if err != nil {
		log.Fatal(err)
	}

	if os.Args[1] == "sign" && certPath != nil {
		// We want the signature to be base64 encoded, but not the certificate
		// So base64 decode the certificate
		cert, err := os.ReadFile(*certPath)
		if err != nil {
			log.Fatal(err)
		}
		certB64Decode, err := base64.StdEncoding.DecodeString(string(cert))
		if err != nil {
			log.Fatal(err)
		}
		if err := os.WriteFile(*certPath, certB64Decode, 0600); err != nil {
			log.Fatal(err)
		}
	}
}
