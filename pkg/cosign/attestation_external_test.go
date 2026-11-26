// Copyright 2026 The Sigstore Authors.
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

package cosign_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sort"
	"testing"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/policy"
	cosign_types "github.com/sigstore/cosign/v2/pkg/types"
	"github.com/sigstore/sigstore/pkg/signature"
)

type payloadProvider struct {
	payload []byte
}

func (p *payloadProvider) Payload() ([]byte, error) {
	return p.payload, nil
}

func (p *payloadProvider) Base64Signature() (string, error) {
	return "", nil
}

// Invariant: if verifyOCIAttestation accepts an envelope, the policy layer must
// read the predicate that was signed, not an unsigned value under a differently
// cased "payload" key.
func TestVerifyAttestationCaseInsensitivePayloadKey(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sv, err := signature.LoadECDSASignerVerifier(priv, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	stmt := func(pt string) string {
		return base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf(`{"_type":"https://in-toto.io/Statement/v0.1","predicateType":%q,"subject":[{"name":"x","digest":{"sha256":"aa"}}],"predicate":{}}`, pt)))
	}
	const signedType = "https://spdx.dev/Document"
	const forgedType = "https://slsa.dev/provenance/v0.2"
	signedB64 := stmt(signedType)
	forgedB64 := stmt(forgedType)
	raw, err := base64.StdEncoding.DecodeString(signedB64)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := sv.SignMessage(bytes.NewReader(dsse.PAE(cosign_types.IntotoPayloadType, raw)))
	if err != nil {
		t.Fatal(err)
	}
	s := base64.StdEncoding.EncodeToString(sig)
	env := func(body string) *payloadProvider {
		return &payloadProvider{payload: []byte(fmt.Sprintf(`{"payloadType":%q,%s,"signatures":[{"keyid":"","sig":%q}]}`, cosign_types.IntotoPayloadType, body, s))}
	}
	cases := map[string]*payloadProvider{
		"honest":             env(fmt.Sprintf(`"payload":%q`, signedB64)),
		"forged_then_signed": env(fmt.Sprintf(`"payload":%q,"Payload":%q`, forgedB64, signedB64)),
		"signed_then_forged": env(fmt.Sprintf(`"Payload":%q,"payload":%q`, signedB64, forgedB64)),
		"dup_lowercase":      env(fmt.Sprintf(`"payload":%q,"payload":%q`, forgedB64, signedB64)),
		"uppercase_only":     env(fmt.Sprintf(`"PAYLOAD":%q`, signedB64)),
	}
	names := make([]string, 0, len(cases))
	for n := range cases {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		a := cases[name]
		sigOK := cosign.VerifyOCIAttestationForTest(context.Background(), sv, a) == nil
		_, pt, perr := policy.AttestationToPayloadJSON(context.Background(), "slsaprovenance", a)
		t.Logf("%-20s sigOK=%v policySees=%q policyErr=%v", name, sigOK, pt, perr)
		if sigOK && perr == nil && pt == forgedType {
			t.Errorf("%s: signature accepted but policy sees the UNSIGNED predicate %q", name, forgedType)
		}
	}
}
