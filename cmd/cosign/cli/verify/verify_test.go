// Copyright 2022 The Sigstore Authors.
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
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
	"github.com/sigstore/cosign/v2/test"
	"github.com/sigstore/sigstore/pkg/signature/payload"
	"github.com/stretchr/testify/assert"
)

func TestPrintVerification(t *testing.T) {
	// while we are adding a more human-readable output for cert extensions, on the other hand
	// we want as backward compatible as possible, so we are keeping the old OIDs field names as well.
	wantPayload := `
[
    {
        "critical": {
            "identity": {
                "docker-reference": "gcr.io/baz/baz"
            },
            "image": {
                "docker-manifest-digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            },
            "type": "cosign container image signature"
        },
        "optional": {
            "1.3.6.1.4.1.57264.1.1": "oidc-issuer",
            "1.3.6.1.4.1.57264.1.2": "myWorkflowTrigger",
            "1.3.6.1.4.1.57264.1.3": "myWorkflowSha",
            "1.3.6.1.4.1.57264.1.4": "myWorkflowName",
            "1.3.6.1.4.1.57264.1.5": "myWorkflowRepository",
            "1.3.6.1.4.1.57264.1.6": "myWorkflowRef",
            "Issuer": "oidc-issuer",
            "Subject": "subject",
            "githubWorkflowName": "myWorkflowName",
            "githubWorkflowRef": "myWorkflowRef",
            "githubWorkflowRepository": "myWorkflowRepository",
            "githubWorkflowSha": "myWorkflowSha",
            "githubWorkflowTrigger": "myWorkflowTrigger"
        }
    }
]
`
	eexts := []pkix.Extension{
		{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 2}, Value: []byte("myWorkflowTrigger")},
		{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 3}, Value: []byte("myWorkflowSha")},
		{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 4}, Value: []byte("myWorkflowName")},
		{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 5}, Value: []byte("myWorkflowRepository")},
		{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 6}, Value: []byte("myWorkflowRef")},
	}
	rootCert, rootKey, _ := test.GenerateRootCa()
	subCert, subKey, _ := test.GenerateSubordinateCa(rootCert, rootKey)
	leafCert, privKey, _ := test.GenerateLeafCert("subject", "oidc-issuer", subCert, subKey, eexts...)
	pemRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCert.Raw})
	pemSub := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: subCert.Raw})
	pemLeaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCert.Raw})

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	// Generate the payload for the image, and check the digest.
	b := bytes.Buffer{}
	dig3, err := name.NewDigest("gcr.io/baz/baz@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", name.StrictValidation)
	if err != nil {
		t.Fatalf("Error creating test dig3.")
	}
	pp, err := (&payload.Cosign{Image: dig3, Annotations: map[string]interface{}{}}).MarshalJSON()
	if err != nil {
		t.Fatalf("Error creating cosign payload")
	}
	fmt.Fprintln(&b, string(pp))

	p := b.Bytes()
	h := sha256.Sum256(p)
	signature, _ := privKey.Sign(rand.Reader, h[:], crypto.SHA256)

	ociSig, _ := static.NewSignature(p,
		base64.StdEncoding.EncodeToString(signature),
		static.WithCertChain(pemLeaf, appendSlices([][]byte{pemSub, pemRoot})))

	captureOutput := func(imgRef string, sigs []oci.Signature, output string, f func(string, []oci.Signature, string)) string {
		reader, writer, err := os.Pipe()
		if err != nil {
			panic(err)
		}
		stdout := os.Stdout
		stderr := os.Stderr
		defer func() {
			os.Stdout = stdout
			os.Stderr = stderr
			log.SetOutput(os.Stderr)
		}()
		os.Stdout = writer
		os.Stderr = writer
		log.SetOutput(writer)
		out := make(chan string)
		wg := new(sync.WaitGroup)
		wg.Add(1)
		go func() {
			var buf bytes.Buffer
			wg.Done()
			io.Copy(&buf, reader)
			out <- buf.String()
		}()
		wg.Wait()
		f(imgRef, sigs, output)
		writer.Close()
		return <-out
	}

	out := captureOutput("", []oci.Signature{ociSig}, "json", PrintVerification)
	prettyPrint := func(b []byte) ([]byte, error) {
		var out bytes.Buffer
		err := json.Indent(&out, b, "", "    ")
		return out.Bytes(), err
	}
	i, err := prettyPrint([]byte(out))
	if err != nil {
		t.Fatal(err.Error())
	}
	assert.JSONEq(t, wantPayload, string(i))
}

func appendSlices(slices [][]byte) []byte {
	var tmp []byte
	for _, s := range slices {
		tmp = append(tmp, s...)
	}
	return tmp
}
