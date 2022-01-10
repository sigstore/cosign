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

package rekor

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/sigstore/cosign/internal/pkg/cosign/payload"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/sigstore/pkg/signature"
)

func mustGetNewSigner(t *testing.T) signature.Signer {
	t.Helper()
	priv, err := cosign.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("cosign.GeneratePrivateKey() failed: %v", err)
	}
	s, err := signature.LoadECDSASignerVerifier(priv, crypto.SHA256)
	if err != nil {
		t.Fatalf("signature.LoadECDSASignerVerifier(key, crypto.SHA256) failed: %v", err)
	}
	return s
}

func TestSigner(t *testing.T) {
	// Need real cert and chain
	payloadSigner := payload.NewSigner(mustGetNewSigner(t))

	// Mock out Rekor client
	var mClient client.Rekor
	mClient.Entries = &MockEntriesClient{}

	testSigner := NewSigner(payloadSigner, &mClient)

	testPayload := "test payload"

	ociSig, pub, err := testSigner.Sign(context.Background(), strings.NewReader(testPayload))
	if err != nil {
		t.Fatalf("Sign() returned error: %v", err)
	}

	// Verify that the OCI signature contains a timestamp.
	timestamp, err := ociSig.Timestamp()
	if err != nil {
		t.Fatalf("ociSig.Timestamp() returned error: %v", err)
	}
	if timestamp == nil {
		t.Fatal("ociSig.Timestamp() missing TUF timestamp, got nil")
	}

	// Verify that the wrapped signer was called.
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
	gotPayload, err := ociSig.Payload()
	if err != nil {
		t.Fatalf("ociSig.Payload() returned error: %v", err)
	}
	if string(gotPayload) != testPayload {
		t.Errorf("ociSig.Payload() returned %q, wanted %q", string(gotPayload), testPayload)
	}
	if err = verifier.VerifySignature(bytes.NewReader(sig), bytes.NewReader(gotPayload)); err != nil {
		t.Errorf("VerifySignature() returned error: %v", err)
	}
}
