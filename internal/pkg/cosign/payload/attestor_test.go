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

package payload

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/pkg/types"
	"github.com/sigstore/sigstore/pkg/signature"
)

func TestDSSEAttestor(t *testing.T) {
	testPayloadType := "atTESTation type"
	testSigner := NewDSSEAttestor(testPayloadType, mustGetNewSigner(t), nil, nil)

	testPayload := "test payload"

	ociSig, pub, err := testSigner.DSSEAttest(context.Background(), strings.NewReader(testPayload))
	if err != nil {
		t.Fatalf("DSSEAttest() returned error: %v", err)
	}

	gotMT, err := ociSig.MediaType()
	if err != nil {
		t.Fatalf("ociSig.MediaType() failed: %v", err)
	}
	if gotMT != types.DssePayloadType {
		t.Errorf("got MediaType() %q, wanted %q", gotMT, types.DssePayloadType)
	}

	verifier, err := signature.LoadVerifier(pub, crypto.SHA256)
	if err != nil {
		t.Fatalf("signature.LoadVerifier(pub) returned error: %v", err)
	}

	gotOCISigPayload, err := ociSig.Payload()
	if err != nil {
		t.Fatalf("ociSig.Payload() returned error: %v", err)
	}

	envelope := dsse.Envelope{}
	if err := json.Unmarshal(gotOCISigPayload, &envelope); err != nil {
		t.Fatalf("json.Unmarshal() failed: %v", err)
	}

	if envelope.PayloadType != testPayloadType {
		t.Errorf("got PayloadType %q, wanted %q", envelope.PayloadType, testPayloadType)
	}

	if len(envelope.Signatures) != 1 {
		t.Errorf("expected a single signature in the envelope, got: %v", envelope.Signatures)
	}

	gotPayload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		t.Fatalf("base64.StdEncoding.DecodeString(envelope.Payload) failed: %v", err)
	}

	gotSig, err := base64.StdEncoding.DecodeString(envelope.Signatures[0].Sig)
	if err != nil {
		t.Fatalf("base64.StdEncoding.DecodeString(envelope.Signatures[0].Sig) failed: %v", err)
	}

	if err = verifier.VerifySignature(bytes.NewReader(gotSig), bytes.NewReader(gotPayload)); err != nil {
		t.Errorf("VerifySignature() returned error: %v", err)
	}
}
