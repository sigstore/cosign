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

package keyless

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/sigstore/sigstore/pkg/signature"
)

func TestKeylessSigner(t *testing.T) {
	testSigner, err := NewSigner()
	if err != nil {
		t.Fatalf("NewSigner() returned error: %v", err)
	}

	testPayload := "test payload"

	ociSig, pub, err := testSigner.Sign(context.Background(), strings.NewReader(testPayload))
	if err != nil {
		t.Fatalf("Sign() returned error: %v", err)
	}

	verifier, err := signature.LoadVerifier(pub, crypto.SHA256)
	if err != nil {
		t.Fatalf("signature.LoadVerifier(pub) returned error: %v", err)
	}

	b64Sig, err := ociSig.Base64Signature()
	if err != nil {
		t.Fatalf("ociSig.Base64Signature() returned error: %v", err)
	}

	sig, err := base64.StdEncoding.DecodeString(b64Sig)
	if err != nil {
		t.Fatalf("base64.StdEncoding.DecodeString(b64Sig) returned error: %v", err)
	}

	err = verifier.VerifySignature(bytes.NewReader(sig), strings.NewReader(testPayload))
	if err != nil {
		t.Fatalf("VerifySignature() returned error: %v", err)
	}
}
