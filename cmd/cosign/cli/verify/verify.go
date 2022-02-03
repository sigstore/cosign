//
// Copyright 2021 The Sigstore Authors.
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

package verify

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/pkg/errors"

	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/pkg/blob"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/pivkey"
	"github.com/sigstore/cosign/pkg/cosign/pkcs11key"
	"github.com/sigstore/cosign/pkg/oci"
	sigs "github.com/sigstore/cosign/pkg/signature"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/payload"
)

// VerifyCommand verifies a signature on a supplied container image
// nolint
type VerifyCommand struct {
	options.RegistryOptions
	CheckClaims    bool
	KeyRef         string
	CertRef        string
	CertEmail      string
	CertOidcIssuer string
	Sk             bool
	Slot           string
	Output         string
	RekorURL       string
	Attachment     string
	Annotations    sigs.AnnotationsMap
	SignatureRef   string
	HashAlgorithm  crypto.Hash
	LocalImage     bool
}

// Exec runs the verification command
func (c *VerifyCommand) Exec(ctx context.Context, images []string) (err error) {
	if len(images) == 0 {
		return flag.ErrHelp
	}

	switch c.Attachment {
	case "sbom", "":
		break
	default:
		return flag.ErrHelp
	}

	// always default to sha256 if the algorithm hasn't been explicitly set
	if c.HashAlgorithm == 0 {
		c.HashAlgorithm = crypto.SHA256
	}

	if !options.OneOf(c.KeyRef, c.CertRef, c.Sk) && !options.EnableExperimental() {
		return &options.KeyParseError{}
	}
	ociremoteOpts, err := c.ClientOpts(ctx)
	if err != nil {
		return errors.Wrap(err, "constructing client options")
	}
	co := &cosign.CheckOpts{
		Annotations:        c.Annotations.Annotations,
		RegistryClientOpts: ociremoteOpts,
		CertEmail:          c.CertEmail,
		CertOidcIssuer:     c.CertOidcIssuer,
		SignatureRef:       c.SignatureRef,
	}
	if c.CheckClaims {
		co.ClaimVerifier = cosign.SimpleClaimVerifier
	}
	if options.EnableExperimental() {
		if c.RekorURL != "" {
			rekorClient, err := rekor.NewClient(c.RekorURL)
			if err != nil {
				return errors.Wrap(err, "creating Rekor client")
			}
			co.RekorClient = rekorClient
		}
		co.RootCerts = fulcio.GetRoots()
	}
	keyRef := c.KeyRef
	certRef := c.CertRef

	// Keys are optional!
	var pubKey signature.Verifier
	switch {
	case keyRef != "":
		pubKey, err = sigs.PublicKeyFromKeyRefWithHashAlgo(ctx, keyRef, c.HashAlgorithm)
		if err != nil {
			return errors.Wrap(err, "loading public key")
		}
		pkcs11Key, ok := pubKey.(*pkcs11key.Key)
		if ok {
			defer pkcs11Key.Close()
		}
	case c.Sk:
		sk, err := pivkey.GetKeyWithSlot(c.Slot)
		if err != nil {
			return errors.Wrap(err, "opening piv token")
		}
		defer sk.Close()
		pubKey, err = sk.Verifier()
		if err != nil {
			return errors.Wrap(err, "initializing piv token verifier")
		}
	case certRef != "":
		cert, err := loadCertFromFileOrURL(c.CertRef)
		if err != nil {
			return err
		}
		pubKey, err = signature.LoadECDSAVerifier(cert.PublicKey.(*ecdsa.PublicKey), crypto.SHA256)
		if err != nil {
			return err
		}
	}
	co.SigVerifier = pubKey

	for _, img := range images {
		if c.LocalImage {
			verified, bundleVerified, err := cosign.VerifyLocalImageSignatures(ctx, img, co)
			if err != nil {
				return err
			}
			PrintVerificationHeader(img, co, bundleVerified)
			PrintVerification(img, verified, c.Output)
		} else {
			ref, err := name.ParseReference(img)
			if err != nil {
				return errors.Wrap(err, "parsing reference")
			}
			ref, err = sign.GetAttachedImageRef(ref, c.Attachment, ociremoteOpts...)
			if err != nil {
				return errors.Wrapf(err, "resolving attachment type %s for image %s", c.Attachment, img)
			}

			verified, bundleVerified, err := cosign.VerifyImageSignatures(ctx, ref, co)
			if err != nil {
				return err
			}

			PrintVerificationHeader(ref.Name(), co, bundleVerified)
			PrintVerification(ref.Name(), verified, c.Output)
		}
	}

	return nil
}

func PrintVerificationHeader(imgRef string, co *cosign.CheckOpts, bundleVerified bool) {
	fmt.Fprintf(os.Stderr, "\nVerification for %s --\n", imgRef)
	fmt.Fprintln(os.Stderr, "The following checks were performed on each of these signatures:")
	if co.ClaimVerifier != nil {
		if co.Annotations != nil {
			fmt.Fprintln(os.Stderr, "  - The specified annotations were verified.")
		}
		fmt.Fprintln(os.Stderr, "  - The cosign claims were validated")
	}
	if bundleVerified {
		fmt.Fprintln(os.Stderr, "  - Existence of the claims in the transparency log was verified offline")
	} else if co.RekorClient != nil {
		fmt.Fprintln(os.Stderr, "  - The claims were present in the transparency log")
		fmt.Fprintln(os.Stderr, "  - The signatures were integrated into the transparency log when the certificate was valid")
	}
	if co.SigVerifier != nil {
		fmt.Fprintln(os.Stderr, "  - The signatures were verified against the specified public key")
	}
	fmt.Fprintln(os.Stderr, "  - Any certificates were verified against the Fulcio roots.")
}

// PrintVerification logs details about the verification to stdout
func PrintVerification(imgRef string, verified []oci.Signature, output string) {
	switch output {
	case "text":
		for _, sig := range verified {
			if cert, err := sig.Cert(); err == nil && cert != nil {
				fmt.Println("Certificate subject: ", sigs.CertSubject(cert))
				if issuerURL := sigs.CertIssuerExtension(cert); issuerURL != "" {
					fmt.Println("Certificate issuer URL: ", issuerURL)
				}
			}

			p, err := sig.Payload()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error fetching payload: %v", err)
				return
			}
			fmt.Println(string(p))
		}

	default:
		if options.EnableExperimental() {
			var output []map[string]interface{}

			for _, sig := range verified {
				out := map[string]interface{}{}

				p, err := sig.Payload()
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error fetching payload: %v", err)
					return
				}

				ss := payload.SimpleContainerImage{}
				if err := json.Unmarshal(p, &ss); err != nil {
					fmt.Println("error decoding the payload:", err.Error())
					return
				}
				out["payload"] = ss

				if cert, err := sig.Cert(); err == nil && cert != nil {
					c := map[string]string{
						"sub": sigs.CertSubject(cert),
					}
					if issuerURL := sigs.CertIssuerExtension(cert); issuerURL != "" {
						c["iss"] = issuerURL
					}
					out["cert"] = c
				}

				if bundle, err := sig.Bundle(); err == nil && bundle != nil {
					out["bundle"] = bundle
				}

				if timestamp, err := sig.Timestamp(); err == nil && timestamp != nil {
					out["timestamp"] = timestamp
				}

				output = append(output, out)
			}

			b, err := json.Marshal(output)
			if err != nil {
				fmt.Println("error when generating the output:", err.Error())
				return
			}

			fmt.Printf("\n%s\n", string(b))
		} else {
			var outputKeys []payload.SimpleContainerImage
			for _, sig := range verified {
				p, err := sig.Payload()
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error fetching payload: %v", err)
					return
				}

				ss := payload.SimpleContainerImage{}
				if err := json.Unmarshal(p, &ss); err != nil {
					fmt.Println("error decoding the payload:", err.Error())
					return
				}

				if cert, err := sig.Cert(); err == nil && cert != nil {
					if ss.Optional == nil {
						ss.Optional = make(map[string]interface{})
					}
					ss.Optional["Subject"] = sigs.CertSubject(cert)
					if issuerURL := sigs.CertIssuerExtension(cert); issuerURL != "" {
						ss.Optional["Issuer"] = issuerURL
					}
				}
				if bundle, err := sig.Bundle(); err == nil && bundle != nil {
					if ss.Optional == nil {
						ss.Optional = make(map[string]interface{})
					}
					ss.Optional["Bundle"] = bundle
				}

				outputKeys = append(outputKeys, ss)
			}

			b, err := json.Marshal(outputKeys)
			if err != nil {
				fmt.Println("error when generating the output:", err.Error())
				return
			}

			fmt.Printf("\n%s\n", string(b))
		}
	}
}

func loadCertFromFileOrURL(path string) (*x509.Certificate, error) {
	pems, err := blob.LoadFileOrURL(path)
	if err != nil {
		return nil, err
	}
	return loadCertFromPEM(pems)
}

func loadCertFromPEM(pems []byte) (*x509.Certificate, error) {
	var out []byte
	out, err := base64.StdEncoding.DecodeString(string(pems))
	if err != nil {
		// not a base64
		out = pems
	}

	certs, err := cryptoutils.UnmarshalCertificatesFromPEM(out)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, errors.New("no certs found in pem file")
	}
	return certs[0], nil
}
