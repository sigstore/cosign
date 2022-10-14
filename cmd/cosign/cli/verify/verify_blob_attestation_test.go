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
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	ssldsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
)

const (
	blobContents                         = "some-payload"
	anotherBlobContents                  = "another-blob"
	blobSLSAProvenanceSignature          = "eyJwYXlsb2FkVHlwZSI6ImFwcGxpY2F0aW9uL3ZuZC5pbi10b3RvK2pzb24iLCJwYXlsb2FkIjoiZXlKZmRIbHdaU0k2SW1oMGRIQnpPaTh2YVc0dGRHOTBieTVwYnk5VGRHRjBaVzFsYm5RdmRqQXVNU0lzSW5CeVpXUnBZMkYwWlZSNWNHVWlPaUpvZEhSd2N6b3ZMM05zYzJFdVpHVjJMM0J5YjNabGJtRnVZMlV2ZGpBdU1pSXNJbk4xWW1wbFkzUWlPbHQ3SW01aGJXVWlPaUppYkc5aUlpd2laR2xuWlhOMElqcDdJbk5vWVRJMU5pSTZJalkxT0RjNE1XTmtOR1ZrT1dKallUWXdaR0ZqWkRBNVpqZGlZamt4TkdKaU5URTFNREpsT0dJMVpEWXhPV1kxTjJZek9XRXhaRFkxTWpVNU5tTmpNalFpZlgxZExDSndjbVZrYVdOaGRHVWlPbnNpWW5WcGJHUmxjaUk2ZXlKcFpDSTZJaklpZlN3aVluVnBiR1JVZVhCbElqb2llQ0lzSW1sdWRtOWpZWFJwYjI0aU9uc2lZMjl1Wm1sblUyOTFjbU5sSWpwN2ZYMTlmUT09Iiwic2lnbmF0dXJlcyI6W3sia2V5aWQiOiIiLCJzaWciOiJNR1lDTVFEWHZhVVAwZmlYdXJUcmZNNmtQNjRPcERCM0pzSlEzbFFHZWE5UmZBOVBCY3JmWTJOc0dxK1J0MzdnMlpqaUpKOENNUUNNY3pzVy9wOGJiekZOSkRqeEhlOFNRdTRTazhBa3htTEdLMVE2R2lUazAzb2hHU3dsZkZRNXMrTWxRTFpGZXpBPSJ9XX0="
	dssePredicateEmptySubject            = "ewogICJwYXlsb2FkVHlwZSI6ICJhcHBsaWNhdGlvbi92bmQuaW4tdG90bytqc29uIiwKICAicGF5bG9hZCI6ICJld29nSUNKZmRIbHdaU0k2SUNKb2RIUndjem92TDJsdUxYUnZkRzh1YVc4dlUzUmhkR1Z0Wlc1MEwzWXdMakVpTEFvZ0lDSndjbVZrYVdOaGRHVlVlWEJsSWpvZ0ltaDBkSEJ6T2k4dmMyeHpZUzVrWlhZdmNISnZkbVZ1WVc1alpTOTJNQzR5SWl3S0lDQWljM1ZpYW1WamRDSTZJRnNLSUNCZExBb2dJQ0p3Y21Wa2FXTmhkR1VpT2lCN0NpQWdJQ0FpWW5WcGJHUmxjaUk2SUhzS0lDQWdJQ0FnSW1sa0lqb2dJaklpQ2lBZ0lDQjlMQW9nSUNBZ0ltSjFhV3hrVkhsd1pTSTZJQ0o0SWl3S0lDQWdJQ0pwYm5adlkyRjBhVzl1SWpvZ2V3b2dJQ0FnSUNBaVkyOXVabWxuVTI5MWNtTmxJam9nZTMwS0lDQWdJSDBLSUNCOUNuMEsiLAogICJzaWduYXR1cmVzIjogWwogICAgewogICAgICAia2V5aWQiOiAiIiwKICAgICAgInNpZyI6ICJNR1lDTVFEWHZhVVAwZmlYdXJUcmZNNmtQNjRPcERCM0pzSlEzbFFHZWE5UmZBOVBCY3JmWTJOc0dxK1J0MzdnMlpqaUpKOENNUUNNY3pzVy9wOGJiekZOSkRqeEhlOFNRdTRTazhBa3htTEdLMVE2R2lUazAzb2hHU3dsZkZRNXMrTWxRTFpGZXpBPSIKICAgIH0KICBdCn0K"
	dssePredicateMissingSha256           = "ewogICJwYXlsb2FkVHlwZSI6ICJhcHBsaWNhdGlvbi92bmQuaW4tdG90bytqc29uIiwKICAicGF5bG9hZCI6ICJld29nSUNKZmRIbHdaU0k2SUNKb2RIUndjem92TDJsdUxYUnZkRzh1YVc4dlUzUmhkR1Z0Wlc1MEwzWXdMakVpTEFvZ0lDSndjbVZrYVdOaGRHVlVlWEJsSWpvZ0ltaDBkSEJ6T2k4dmMyeHpZUzVrWlhZdmNISnZkbVZ1WVc1alpTOTJNQzR5SWl3S0lDQWljM1ZpYW1WamRDSTZJRnNLSUNBZ0lIc0tJQ0FnSUNBZ0ltNWhiV1VpT2lBaVlteHZZaUlzQ2lBZ0lDQWdJQ0prYVdkbGMzUWlPaUI3Q2lBZ0lDQWdJQ0FnSW01dmRITm9ZVEkxTmlJNklDSTJOVGczT0RGalpEUmxaRGxpWTJFMk1HUmhZMlF3T1dZM1ltSTVNVFJpWWpVeE5UQXlaVGhpTldRMk1UbG1OVGRtTXpsaE1XUTJOVEkxT1Raall6STBJZ29nSUNBZ0lDQjlDaUFnSUNCOUNpQWdYU3dLSUNBaWNISmxaR2xqWVhSbElqb2dld29nSUNBZ0ltSjFhV3hrWlhJaU9pQjdDaUFnSUNBZ0lDSnBaQ0k2SUNJeUlnb2dJQ0FnZlN3S0lDQWdJQ0ppZFdsc1pGUjVjR1VpT2lBaWVDSXNDaUFnSUNBaWFXNTJiMk5oZEdsdmJpSTZJSHNLSUNBZ0lDQWdJbU52Ym1acFoxTnZkWEpqWlNJNklIdDlDaUFnSUNCOUNpQWdmUXA5Q2c9PSIsCiAgInNpZ25hdHVyZXMiOiBbCiAgICB7CiAgICAgICJrZXlpZCI6ICIiLAogICAgICAic2lnIjogIk1HWUNNUURYdmFVUDBmaVh1clRyZk02a1A2NE9wREIzSnNKUTNsUUdlYTlSZkE5UEJjcmZZMk5zR3ErUnQzN2cyWmppSko4Q01RQ01jenNXL3A4YmJ6Rk5KRGp4SGU4U1F1NFNrOEFreG1MR0sxUTZHaVRrMDNvaEdTd2xmRlE1cytNbFFMWkZlekE9IgogICAgfQogIF0KfQo="
	dssePredicateMultipleSubjects        = "ewogICJwYXlsb2FkVHlwZSI6ICJhcHBsaWNhdGlvbi92bmQuaW4tdG90bytqc29uIiwKICAicGF5bG9hZCI6ICJld29nSUNKZmRIbHdaU0k2SUNKb2RIUndjem92TDJsdUxYUnZkRzh1YVc4dlUzUmhkR1Z0Wlc1MEwzWXdMakVpTEFvZ0lDSndjbVZrYVdOaGRHVlVlWEJsSWpvZ0ltaDBkSEJ6T2k4dmMyeHpZUzVrWlhZdmNISnZkbVZ1WVc1alpTOTJNQzR5SWl3S0lDQWljM1ZpYW1WamRDSTZJRnNLSUNBZ0lIc0tJQ0FnSUNBZ0ltNWhiV1VpT2lBaVlXNXZkR2hsY21Kc2IySWlMQW9nSUNBZ0lDQWlaR2xuWlhOMElqb2dld29nSUNBZ0lDQWdJQ0p6YUdFeU5UWWlPaUFpTlRnek1HWXhOVGd5WVRNek1HRTRNbVEyWkRkak5qRmtNV0UxWVdRM01EWmtOMk0zTkdSak5USTFOVGMxWlRjeE9EVmlObU14WWpJd05UY3hOekkyTmlJS0lDQWdJQ0FnZlFvZ0lDQWdmU3dLSUNBZ0lIc0tJQ0FnSUNBZ0ltNWhiV1VpT2lBaVlteHZZaUlzQ2lBZ0lDQWdJQ0prYVdkbGMzUWlPaUI3Q2lBZ0lDQWdJQ0FnSW5Ob1lUSTFOaUk2SUNJMk5UZzNPREZqWkRSbFpEbGlZMkUyTUdSaFkyUXdPV1kzWW1JNU1UUmlZalV4TlRBeVpUaGlOV1EyTVRsbU5UZG1NemxoTVdRMk5USTFPVFpqWXpJMElnb2dJQ0FnSUNCOUNpQWdJQ0I5Q2lBZ1hTd0tJQ0FpY0hKbFpHbGpZWFJsSWpvZ2V3b2dJQ0FnSW1KMWFXeGtaWElpT2lCN0NpQWdJQ0FnSUNKcFpDSTZJQ0l5SWdvZ0lDQWdmU3dLSUNBZ0lDSmlkV2xzWkZSNWNHVWlPaUFpZUNJc0NpQWdJQ0FpYVc1MmIyTmhkR2x2YmlJNklIc0tJQ0FnSUNBZ0ltTnZibVpwWjFOdmRYSmpaU0k2SUh0OUNpQWdJQ0I5Q2lBZ2ZRcDlDZz09IiwKICAic2lnbmF0dXJlcyI6IFsKICAgIHsKICAgICAgImtleWlkIjogIiIsCiAgICAgICJzaWciOiAiTUdZQ01RRFh2YVVQMGZpWHVyVHJmTTZrUDY0T3BEQjNKc0pRM2xRR2VhOVJmQTlQQmNyZlkyTnNHcStSdDM3ZzJaamlKSjhDTVFDTWN6c1cvcDhiYnpGTkpEanhIZThTUXU0U2s4QWt4bUxHSzFRNkdpVGswM29oR1N3bGZGUTVzK01sUUxaRmV6QT0iCiAgICB9CiAgXQp9Cg=="
	dssePredicateMultipleSubjectsInvalid = "ewogICJwYXlsb2FkVHlwZSI6ICJhcHBsaWNhdGlvbi92bmQuaW4tdG90bytqc29uIiwKICAicGF5bG9hZCI6ICJld29nSUNKZmRIbHdaU0k2SUNKb2RIUndjem92TDJsdUxYUnZkRzh1YVc4dlUzUmhkR1Z0Wlc1MEwzWXdMakVpTEFvZ0lDSndjbVZrYVdOaGRHVlVlWEJsSWpvZ0ltaDBkSEJ6T2k4dmMyeHpZUzVrWlhZdmNISnZkbVZ1WVc1alpTOTJNQzR5SWl3S0lDQWljM1ZpYW1WamRDSTZJRnNLSUNBZ0lIc0tJQ0FnSUNBZ0ltNWhiV1VpT2lBaVlXNXZkR2hsY21Kc2IySWlMQW9nSUNBZ0lDQWlaR2xuWlhOMElqb2dld29nSUNBZ0lDQWdJQ0p6YUdFeU5UWWlPaUFpTlRnek1HWXhOVGd5WVRNek1HRTRNbVEyWkRkak5qRmtNV0UxWVdRM01EWmtOMk0zTkdSak5USTFOVGMxWlRjeE9EVmlObU14WWpJd05UY3hOekkyTmlJS0lDQWdJQ0FnZlFvZ0lDQWdmU3dLSUNBZ0lIc0tJQ0FnSUNBZ0ltNWhiV1VpT2lBaVlteHZZaUlzQ2lBZ0lDQWdJQ0prYVdkbGMzUWlPaUI3Q2lBZ0lDQWdJQ0FnSW5Ob1lUSTFOaUk2SUNJMU9ETXdaakUxT0RKaE16TXdZVGd5WkRaa04yTTJNV1F4WVRWaFpEY3dObVEzWXpjMFpHTTFNalUxTnpWbE56RTROV0kyWXpGaU1qQTFOekUzTWpZMklnb2dJQ0FnSUNCOUNpQWdJQ0I5Q2lBZ1hTd0tJQ0FpY0hKbFpHbGpZWFJsSWpvZ2V3b2dJQ0FnSW1KMWFXeGtaWElpT2lCN0NpQWdJQ0FnSUNKcFpDSTZJQ0l5SWdvZ0lDQWdmU3dLSUNBZ0lDSmlkV2xzWkZSNWNHVWlPaUFpZUNJc0NpQWdJQ0FpYVc1MmIyTmhkR2x2YmlJNklIc0tJQ0FnSUNBZ0ltTnZibVpwWjFOdmRYSmpaU0k2SUh0OUNpQWdJQ0I5Q2lBZ2ZRcDlDZz09IiwKICAic2lnbmF0dXJlcyI6IFsKICAgIHsKICAgICAgImtleWlkIjogIiIsCiAgICAgICJzaWciOiAiTUdZQ01RRFh2YVVQMGZpWHVyVHJmTTZrUDY0T3BEQjNKc0pRM2xRR2VhOVJmQTlQQmNyZlkyTnNHcStSdDM3ZzJaamlKSjhDTVFDTWN6c1cvcDhiYnpGTkpEanhIZThTUXU0U2s4QWt4bUxHSzFRNkdpVGswM29oR1N3bGZGUTVzK01sUUxaRmV6QT0iCiAgICB9CiAgXQp9Cg=="
)

func TestVerifyBlobAttestation(t *testing.T) {
	tmpdir := t.TempDir()
	blobPath := filepath.Join(tmpdir, "blob")
	if err := os.WriteFile(blobPath, []byte(blobContents), 0755); err != nil {
		t.Fatal(err)
	}
	anotherBlobPath := filepath.Join(tmpdir, "another-blob")
	if err := os.WriteFile(anotherBlobPath, []byte(anotherBlobContents), 0755); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)

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

			// Verify the signature on the attestation against the provided public key
			env := ssldsse.Envelope{}
			if err := json.Unmarshal(decodedSig, &env); err != nil {
				t.Fatal(err)
			}

			err = verifyBlobAttestation(env, test.blobPath, test.predicateType)
			if (err != nil) != test.shouldErr {
				t.Fatalf("verifyBlobAttestation()= %s, expected shouldErr=%t ", err, test.shouldErr)
			}
		})
	}
}
