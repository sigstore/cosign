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

//go:build e2e && cross

package test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"path"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/attach"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	cliverify "github.com/sigstore/cosign/v2/cmd/cosign/cli/verify"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
)

func TestAttachSignature(t *testing.T) {
	ctx := context.Background()

	repo, stop := reg(t)
	defer stop()
	td := t.TempDir()

	imgName := path.Join(repo, "cosign-attach-e2e")

	imgRef, desc, cleanup := mkimage(t, imgName)
	defer cleanup()

	// Generate payload
	b := bytes.Buffer{}
	must(generate.GenerateCmd(context.Background(), options.RegistryOptions{}, imgName, nil, &b), t)
	payloadRef := mkfile(b.String(), td, t)
	hash := sha256.Sum256(b.Bytes())

	// Scenario 1: attach a single signature with certificate and certificate chain to an artifact
	// and verify it using the root certificate.
	rootCert1, rootKey1, _ := GenerateRootCa()
	pemRoot1 := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCert1.Raw})
	pemRootRef1 := mkfile(string(pemRoot1), td, t)
	subCert1, subKey1, _ := GenerateSubordinateCa(rootCert1, rootKey1)
	leafCert1, privKey1, _ := GenerateLeafCert("foo@example.com", "oidc-issuer", subCert1, subKey1)
	pemSub1 := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: subCert1.Raw})
	pemLeaf1 := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCert1.Raw})
	pemLeafRef1 := mkfile(string(pemLeaf1), td, t)
	certChainRef1 := mkfile(string(append(pemSub1[:], pemRoot1[:]...)), td, t)

	signature1, _ := privKey1.Sign(rand.Reader, hash[:], crypto.SHA256)
	b64signature1 := base64.StdEncoding.EncodeToString([]byte(signature1))
	sigRef1 := mkfile(b64signature1, td, t)

	err := attach.SignatureCmd(ctx, options.RegistryOptions{}, sigRef1, payloadRef, pemLeafRef1, certChainRef1, "", "", imgName)
	must(err, t)

	remoteSigRef, err := name.ParseReference(fmt.Sprintf("%s:sha256-%s.sig", imgRef, strings.Split(desc.Digest.String(), ":")[1]), name.WeakValidation)
	must(err, t)

	si, err := ociremote.SignedImage(remoteSigRef, ociremote.WithRemoteOptions(registryClientOpts(ctx)...))
	must(err, t)

	manifest, err := si.Manifest()
	must(err, t)

	equals(manifest.Config.MediaType, types.MediaType("application/vnd.oci.image.config.v1+json"), t)
	if len(manifest.Layers) != 1 {
		t.Fatal("expected exactly one layer")
	}
	_, certOk := manifest.Layers[0].Annotations["dev.sigstore.cosign/certificate"]
	equals(certOk, true, t)
	_, chainOk := manifest.Layers[0].Annotations["dev.sigstore.cosign/chain"]
	equals(chainOk, true, t)

	verifyCmd := cliverify.VerifyCommand{
		IgnoreSCT:  true,
		IgnoreTlog: true,
		CertChain:  pemRootRef1,
		CertVerifyOptions: options.CertVerifyOptions{
			CertOidcIssuerRegexp: ".*",
			CertIdentityRegexp:   ".*",
		},
	}
	args := []string{imgName}
	must(verifyCmd.Exec(ctx, args), t)

	// Scenario 2: Attaches second signature with another certificate and  certificate chain to the
	// same artifact and verify it using both root certificates separately.
	rootCert2, rootKey2, _ := GenerateRootCa()
	pemRoot2 := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCert2.Raw})
	pemRootRef2 := mkfile(string(pemRoot2), td, t)
	subCert2, subKey2, _ := GenerateSubordinateCa(rootCert2, rootKey2)
	leafCert2, privKey2, _ := GenerateLeafCert("foo@exampleclient.com", "oidc-issuer", subCert2, subKey2)
	pemSub2 := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: subCert2.Raw})
	pemLeaf2 := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCert2.Raw})
	pemLeafRef2 := mkfile(string(pemLeaf2), td, t)
	certChainRef2 := mkfile(string(append(pemSub2[:], pemRoot2[:]...)), td, t)

	signature2, _ := privKey2.Sign(rand.Reader, hash[:], crypto.SHA256)
	b64signature2 := base64.StdEncoding.EncodeToString([]byte(signature2))
	sigRef2 := mkfile(b64signature2, td, t)

	err = attach.SignatureCmd(ctx, options.RegistryOptions{}, sigRef2, payloadRef, pemLeafRef2, certChainRef2, "", "", imgName)
	must(err, t)

	// verify using first root certificate
	verifyCmd = cliverify.VerifyCommand{
		IgnoreSCT:  true,
		IgnoreTlog: true,
		CertChain:  pemRootRef1,
		CertVerifyOptions: options.CertVerifyOptions{
			CertOidcIssuerRegexp: ".*",
			CertIdentityRegexp:   ".*",
		},
	}
	args = []string{imgName}
	must(verifyCmd.Exec(ctx, args), t)

	// verify using second root cert
	verifyCmd = cliverify.VerifyCommand{
		IgnoreSCT:  true,
		IgnoreTlog: true,
		CertChain:  pemRootRef2,
		CertVerifyOptions: options.CertVerifyOptions{
			CertOidcIssuerRegexp: ".*",
			CertIdentityRegexp:   ".*",
		},
	}
	args = []string{imgName}
	must(verifyCmd.Exec(ctx, args), t)
}
