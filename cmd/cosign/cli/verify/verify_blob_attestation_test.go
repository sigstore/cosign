// Copyright 2022 the Sigstore Authors.
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
	"encoding/base64"
	"os"
	"testing"

	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
)

const pubkey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESF79b1ToAtoakhBOHEU5UjnEiihV
gZPFIp557+TOoDxf14FODWc+sIPETk0OgCplAk60doVXbCv33IU4rXZHrg==
-----END PUBLIC KEY-----
`

const (
	blobContents                         = "some-payload"
	anotherBlobContents                  = "another-blob"
	blobSLSAProvenanceSignature          = "eyJwYXlsb2FkVHlwZSI6ImFwcGxpY2F0aW9uL3ZuZC5pbi10b3RvK2pzb24iLCJwYXlsb2FkIjoiZXlKZmRIbHdaU0k2SW1oMGRIQnpPaTh2YVc0dGRHOTBieTVwYnk5VGRHRjBaVzFsYm5RdmRqQXVNU0lzSW5CeVpXUnBZMkYwWlZSNWNHVWlPaUpvZEhSd2N6b3ZMM05zYzJFdVpHVjJMM0J5YjNabGJtRnVZMlV2ZGpBdU1pSXNJbk4xWW1wbFkzUWlPbHQ3SW01aGJXVWlPaUppYkc5aUlpd2laR2xuWlhOMElqcDdJbk5vWVRJMU5pSTZJalkxT0RjNE1XTmtOR1ZrT1dKallUWXdaR0ZqWkRBNVpqZGlZamt4TkdKaU5URTFNREpsT0dJMVpEWXhPV1kxTjJZek9XRXhaRFkxTWpVNU5tTmpNalFpZlgxZExDSndjbVZrYVdOaGRHVWlPbnNpWW5WcGJHUmxjaUk2ZXlKcFpDSTZJaklpZlN3aVluVnBiR1JVZVhCbElqb2llQ0lzSW1sdWRtOWpZWFJwYjI0aU9uc2lZMjl1Wm1sblUyOTFjbU5sSWpwN2ZYMTlmUT09Iiwic2lnbmF0dXJlcyI6W3sia2V5aWQiOiIiLCJzaWciOiJNRVVDSUE4S2pacWtydDkwZnpCb2pTd3d0ajNCcWI0MUU2cnV4UWs5N1RMbnB6ZFlBaUVBek9Bak9Uenl2VEhxYnBGREFuNnpocmc2RVp2N2t4SzVmYVJvVkdZTWgyYz0ifV19"
	dssePredicateEmptySubject            = "eyJwYXlsb2FkVHlwZSI6ImFwcGxpY2F0aW9uL3ZuZC5pbi10b3RvK2pzb24iLCJwYXlsb2FkIjoiZXlKZmRIbHdaU0k2SW1oMGRIQnpPaTh2YVc0dGRHOTBieTVwYnk5VGRHRjBaVzFsYm5RdmRqQXVNU0lzSW5CeVpXUnBZMkYwWlZSNWNHVWlPaUpvZEhSd2N6b3ZMM05zYzJFdVpHVjJMM0J5YjNabGJtRnVZMlV2ZGpBdU1pSXNJbk4xWW1wbFkzUWlPbHRkTENKd2NtVmthV05oZEdVaU9uc2lZblZwYkdSbGNpSTZleUpwWkNJNklqSWlmU3dpWW5WcGJHUlVlWEJsSWpvaWVDSXNJbWx1ZG05allYUnBiMjRpT25zaVkyOXVabWxuVTI5MWNtTmxJanA3ZlgxOWZRPT0iLCJzaWduYXR1cmVzIjpbeyJrZXlpZCI6IiIsInNpZyI6Ik1FWUNJUUNrTEV2NkhZZ0svZDdUK0N3NTdXbkZGaHFUTC9WalAyVDA5Q2t1dk1nbDRnSWhBT1hBM0lhWWg1M1FscVk1eVU4cWZxRXJma2tGajlEakZnaWovUTQ2NnJSViJ9XX0="
	dssePredicateMissingSha256           = "eyJwYXlsb2FkVHlwZSI6ImFwcGxpY2F0aW9uL3ZuZC5pbi10b3RvK2pzb24iLCJwYXlsb2FkIjoiZXlKZmRIbHdaU0k2SW1oMGRIQnpPaTh2YVc0dGRHOTBieTVwYnk5VGRHRjBaVzFsYm5RdmRqQXVNU0lzSW5CeVpXUnBZMkYwWlZSNWNHVWlPaUpvZEhSd2N6b3ZMM05zYzJFdVpHVjJMM0J5YjNabGJtRnVZMlV2ZGpBdU1pSXNJbk4xWW1wbFkzUWlPbHQ3SW01aGJXVWlPaUppYkc5aUlpd2laR2xuWlhOMElqcDdmWDFkTENKd2NtVmthV05oZEdVaU9uc2lZblZwYkdSbGNpSTZleUpwWkNJNklqSWlmU3dpWW5WcGJHUlVlWEJsSWpvaWVDSXNJbWx1ZG05allYUnBiMjRpT25zaVkyOXVabWxuVTI5MWNtTmxJanA3ZlgxOWZRPT0iLCJzaWduYXR1cmVzIjpbeyJrZXlpZCI6IiIsInNpZyI6Ik1FVUNJQysvM2M4RFo1TGFZTEx6SFZGejE3ZmxHUENlZXVNZ2tIKy8wa2s1cFFLUEFpRUFqTStyYnBBRlJybDdpV0I2Vm9BYVZPZ3U3NjRRM0JKdHI1bHk4VEFHczNrPSJ9XX0="
	dssePredicateMultipleSubjects        = "eyJwYXlsb2FkVHlwZSI6ImFwcGxpY2F0aW9uL3ZuZC5pbi10b3RvK2pzb24iLCJwYXlsb2FkIjoiZXlKZmRIbHdaU0k2SW1oMGRIQnpPaTh2YVc0dGRHOTBieTVwYnk5VGRHRjBaVzFsYm5RdmRqQXVNU0lzSW5CeVpXUnBZMkYwWlZSNWNHVWlPaUpvZEhSd2N6b3ZMM05zYzJFdVpHVjJMM0J5YjNabGJtRnVZMlV2ZGpBdU1pSXNJbk4xWW1wbFkzUWlPbHQ3SW01aGJXVWlPaUppYkc5aUlpd2laR2xuWlhOMElqcDdJbk5vWVRJMU5pSTZJalkxT0RjNE1XTmtOR1ZrT1dKallUWXdaR0ZqWkRBNVpqZGlZamt4TkdKaU5URTFNREpsT0dJMVpEWXhPV1kxTjJZek9XRXhaRFkxTWpVNU5tTmpNalFpZlgwc2V5SnVZVzFsSWpvaWIzUm9aWElpTENKa2FXZGxjM1FpT25zaWMyaGhNalUySWpvaU1HUmhOVFU1WXpKbU1USTNNak13WVRGbVlXSmpabUppTWpCa05XUmlPR1JpWVRjMk5Ua3lNMk0yWldaak5tWTBPRE14TmpVeE1UbGpOR015WXpWa05DSjlmVjBzSW5CeVpXUnBZMkYwWlNJNmV5SmlkV2xzWkdWeUlqcDdJbWxrSWpvaU1pSjlMQ0ppZFdsc1pGUjVjR1VpT2lKNElpd2lhVzUyYjJOaGRHbHZiaUk2ZXlKamIyNW1hV2RUYjNWeVkyVWlPbnQ5ZlgxOSIsInNpZ25hdHVyZXMiOlt7ImtleWlkIjoiIiwic2lnIjoiTUVZQ0lRQ20yR2FwNzRzbDkyRC80V2FoWHZiVHFrNFVCaHZsb3oreDZSZm1NQXUyaWdJaEFNcXRFV29DalpGdkpmZWJxRDJFank3aTlHaGc0a0V0WE51bVdLbVBtdEphIn1dfQ=="
	dssePredicateMultipleSubjectsInvalid = "eyJwYXlsb2FkVHlwZSI6ImFwcGxpY2F0aW9uL3ZuZC5pbi10b3RvK2pzb24iLCJwYXlsb2FkIjoiZXlKZmRIbHdaU0k2SW1oMGRIQnpPaTh2YVc0dGRHOTBieTVwYnk5VGRHRjBaVzFsYm5RdmRqQXVNU0lzSW5CeVpXUnBZMkYwWlZSNWNHVWlPaUpvZEhSd2N6b3ZMM05zYzJFdVpHVjJMM0J5YjNabGJtRnVZMlV2ZGpBdU1pSXNJbk4xWW1wbFkzUWlPbHQ3SW01aGJXVWlPaUppYkc5aUlpd2laR2xuWlhOMElqcDdJbk5vWVRJMU5pSTZJbUUyT0RJelpqbGpOekEyTWpCalltWmpOVGt4T0dJMVpUWmtOR0ZoTVRjMFlUaGhNakJrTlRaa1lUVm1NVEEyWWpZMU5qSTNOR013TldRMlptVXhZVGNpZlgwc2V5SnVZVzFsSWpvaWIzUm9aWElpTENKa2FXZGxjM1FpT25zaWMyaGhNalUySWpvaU1HUmhOVFU1WXpKbU1USTNNak13WVRGbVlXSmpabUppTWpCa05XUmlPR1JpWVRjMk5Ua3lNMk0yWldaak5tWTBPRE14TmpVeE1UbGpOR015WXpWa05DSjlmVjBzSW5CeVpXUnBZMkYwWlNJNmV5SmlkV2xzWkdWeUlqcDdJbWxrSWpvaU1pSjlMQ0ppZFdsc1pGUjVjR1VpT2lKNElpd2lhVzUyYjJOaGRHbHZiaUk2ZXlKamIyNW1hV2RUYjNWeVkyVWlPbnQ5ZlgxOSIsInNpZ25hdHVyZXMiOlt7ImtleWlkIjoiIiwic2lnIjoiTUVVQ0lRRGhZbCtWUlBtcWFJc2xxdS9yWGRVbnc2VmpQcXR4RG84bHdqc3p1cWl6MmdJZ0NNRVVlcUZ5RkFZejcyM2IvSTI2L0p3K0U3YkFLMExqeElsUExvTGxPczQ9In1dfQ=="
)

func TestVerifyBlobAttestation(t *testing.T) {
	ctx := context.Background()
	td := t.TempDir()
	defer os.RemoveAll(td)

	blobPath := writeBlobFile(t, td, blobContents, "blob")
	anotherBlobPath := writeBlobFile(t, td, anotherBlobContents, "other-blob")
	keyRef := writeBlobFile(t, td, pubkey, "cosign.pub")

	tests := []struct {
		description   string
		blobPath      string
		signature     string
		predicateType string
		shouldErr     bool
	}{
		{
			description:   "verify a slsaprovenance predicate",
			predicateType: "slsaprovenance",
			blobPath:      blobPath,
			signature:     blobSLSAProvenanceSignature,
		}, {
			description:   "fail with incorrect predicate",
			signature:     blobSLSAProvenanceSignature,
			blobPath:      blobPath,
			predicateType: "custom",
			shouldErr:     true,
		}, {
			description: "fail with incorrect blob",
			signature:   blobSLSAProvenanceSignature,
			blobPath:    anotherBlobPath,
			shouldErr:   true,
		}, {
			description: "dsse envelope predicate has no subject",
			signature:   dssePredicateEmptySubject,
			blobPath:    blobPath,
			shouldErr:   true,
		}, {
			description: "dsse envelope predicate missing sha256 digest",
			signature:   dssePredicateMissingSha256,
			blobPath:    blobPath,
			shouldErr:   true,
		}, {
			description:   "dsse envelope has multiple subjects, one is valid",
			predicateType: "slsaprovenance",
			signature:     dssePredicateMultipleSubjects,
			blobPath:      blobPath,
		}, {
			description:   "dsse envelope has multiple subjects, none has correct sha256 digest",
			predicateType: "slsaprovenance",
			signature:     dssePredicateMultipleSubjectsInvalid,
			blobPath:      blobPath,
			shouldErr:     true,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			decodedSig, err := base64.StdEncoding.DecodeString(test.signature)
			if err != nil {
				t.Fatal(err)
			}
			sigRef := writeBlobFile(t, td, string(decodedSig), "signature")

			cmd := VerifyBlobAttestationCommand{
				KeyOpts:       options.KeyOpts{KeyRef: keyRef},
				SignaturePath: sigRef,
				IgnoreTlog:    true,
				CheckClaims:   true,
				PredicateType: test.predicateType,
			}
			err = cmd.Exec(ctx, test.blobPath)

			if (err != nil) != test.shouldErr {
				t.Fatalf("verifyBlobAttestation()= %s, expected shouldErr=%t ", err, test.shouldErr)
			}
		})
	}
}

func TestVerifyBlobAttestationPolicy(t *testing.T) {
	ctx := context.Background()
	td := t.TempDir()
	defer os.RemoveAll(td)

	blobPath := writeBlobFile(t, td, blobContents, "blob")
	keyRef := writeBlobFile(t, td, pubkey, "cosign.pub")

	validPolicy1 := writeBlobFile(t, td, "predicateType: \"https://slsa.dev/provenance/v0.2\"", "valid-policy1.cue")
	validPolicy2 := writeBlobFile(t, td, "predicate: { builder: { id: \"2\" } }", "valid-policy2.cue")
	invalidPolicyRef := writeBlobFile(t, td, "predicateType: \"cosign.sigstore.dev/attestation/v1\"", "invalid-policy.cue")

	regoPolicy1 := writeBlobFile(t, td, `package signature
	allow {
	  input.predicateType == "https://slsa.dev/provenance/v0.2"
	}`, "valid-policy1.rego")
	invalidRegoPolicy := writeBlobFile(t, td, `package signature
	allow {
	  input.predicateType == "cosign.sigstore.dev/attestation/v1"
	}`, "invalid-policy1.rego")

	tests := []struct {
		description   string
		blobPath      string
		signature     string
		predicateType string
		policies      []string
		shouldErr     bool
	}{
		{
			description:   "verify a slsaprovenance predicate with policy",
			predicateType: "slsaprovenance",
			blobPath:      blobPath,
			policies:      []string{validPolicy1},
			signature:     blobSLSAProvenanceSignature,
		}, {
			description:   "verify a slsaprovenance predicate with multi-policy",
			signature:     blobSLSAProvenanceSignature,
			blobPath:      blobPath,
			policies:      []string{validPolicy1, validPolicy2},
			predicateType: "slsaprovenance",
		}, {
			description:   "err does not match policy",
			signature:     blobSLSAProvenanceSignature,
			blobPath:      blobPath,
			policies:      []string{invalidPolicyRef},
			predicateType: "slsaprovenance",
			shouldErr:     true,
		},
		{
			description:   "err does not match one of two policy",
			signature:     blobSLSAProvenanceSignature,
			blobPath:      blobPath,
			policies:      []string{invalidPolicyRef, validPolicy1},
			predicateType: "slsaprovenance",
			shouldErr:     true,
		},
		{
			description:   "rego and cue policy",
			signature:     blobSLSAProvenanceSignature,
			blobPath:      blobPath,
			policies:      []string{regoPolicy1, validPolicy1},
			predicateType: "slsaprovenance",
		},
		{
			description:   "rego policy",
			signature:     blobSLSAProvenanceSignature,
			blobPath:      blobPath,
			policies:      []string{regoPolicy1},
			predicateType: "slsaprovenance",
		},
		{
			description:   "invalid rego policy",
			signature:     blobSLSAProvenanceSignature,
			blobPath:      blobPath,
			policies:      []string{invalidRegoPolicy},
			predicateType: "slsaprovenance",
			shouldErr:     true,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			decodedSig, err := base64.StdEncoding.DecodeString(test.signature)
			if err != nil {
				t.Fatal(err)
			}
			sigRef := writeBlobFile(t, td, string(decodedSig), "signature")

			cmd := VerifyBlobAttestationCommand{
				KeyOpts:       options.KeyOpts{KeyRef: keyRef},
				SignaturePath: sigRef,
				IgnoreTlog:    true,
				CheckClaims:   true,
				PredicateType: test.predicateType,
				Policies:      test.policies,
			}
			err = cmd.Exec(ctx, test.blobPath)

			if (err != nil) != test.shouldErr {
				t.Fatalf("verifyBlobAttestation()= %s, expected shouldErr=%t ", err, test.shouldErr)
			}
		})
	}
}
