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

package tsa

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/cosign/internal/pkg/cosign/payload"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/sigstore/pkg/signature"
	tsaclient "github.com/sigstore/timestamp-authority/pkg/client"
	"github.com/sigstore/timestamp-authority/pkg/server"
	"github.com/spf13/viper"
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
	// TODO: Replace with a full TSA mock client, related to https://github.com/sigstore/timestamp-authority/issues/146
	viper.Set("timestamp-signer", "memory")
	apiServer := server.NewRestAPIServer("localhost", 0, []string{"http"}, 10*time.Second, 10*time.Second)
	server := httptest.NewServer(apiServer.GetHandler())
	t.Cleanup(server.Close)

	// Need real cert and chain
	payloadSigner := payload.NewSigner(mustGetNewSigner(t))

	client, err := tsaclient.GetTimestampClient(server.URL)
	if err != nil {
		t.Error(err)
	}

	testSigner := NewSigner(payloadSigner, client)

	testPayload := "test payload"

	ociSig, pub, err := testSigner.Sign(context.Background(), strings.NewReader(testPayload))
	if err != nil {
		t.Fatalf("Sign() returned error: %v", err)
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
