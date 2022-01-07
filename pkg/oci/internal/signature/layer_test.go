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

package signature

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/pkg/cosign/bundle"
	"github.com/sigstore/cosign/pkg/oci"
	"github.com/theupdateframework/go-tuf/data"
)

func mustDecode(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err.Error())
	}
	return b
}

func TestSignature(t *testing.T) {
	layer, err := random.Layer(300 /* byteSize */, types.DockerLayer)
	if err != nil {
		t.Fatalf("random.Layer() = %v", err)
	}
	digest, err := layer.Digest()
	if err != nil {
		t.Fatalf("Digest() = %v", err)
	}
	ts, _ := time.Parse(time.RFC3339, "2022-01-15T00:39:22Z")

	tests := []struct {
		name             string
		l                *sigLayer
		wantPayloadErr   error
		wantSig          string
		wantSigErr       error
		wantCert         bool
		wantCertErr      error
		wantChain        int
		wantChainErr     error
		wantBundle       *bundle.RekorBundle
		wantBundleErr    error
		wantTimestamp    *oci.Timestamp
		wantTimestampErr error
	}{{
		name: "just payload and signature",
		l: &sigLayer{
			Layer: layer,
			desc: v1.Descriptor{
				Digest: digest,
				Annotations: map[string]string{
					sigkey: "blah",
				},
			},
		},
		wantSig: "blah",
	}, {
		name: "with empty other keys",
		l: &sigLayer{
			Layer: layer,
			desc: v1.Descriptor{
				Digest: digest,
				Annotations: map[string]string{
					sigkey:       "blah",
					certkey:      "",
					chainkey:     "",
					BundleKey:    "",
					TimestampKey: "",
				},
			},
		},
		wantSig: "blah",
	}, {
		name: "missing signature",
		l: &sigLayer{
			Layer: layer,
			desc: v1.Descriptor{
				Digest: digest,
			},
		},
		wantSigErr: fmt.Errorf("signature layer %s is missing %q annotation", digest, sigkey),
	}, {
		name: "min plus bad bundle",
		l: &sigLayer{
			Layer: layer,
			desc: v1.Descriptor{
				Digest: digest,
				Annotations: map[string]string{
					sigkey:    "blah",
					BundleKey: `}`,
				},
			},
		},
		wantSig:       "blah",
		wantBundleErr: errors.New(`unmarshaling bundle: invalid character '}' looking for beginning of value`),
	}, {
		name: "min plus bad timestamp",
		l: &sigLayer{
			Layer: layer,
			desc: v1.Descriptor{
				Digest: digest,
				Annotations: map[string]string{
					sigkey:       "blah",
					TimestampKey: `}`,
				},
			},
		},
		wantSig:          "blah",
		wantTimestampErr: errors.New(`unmarshaling timestamp: invalid character '}' looking for beginning of value`),
	}, {
		name: "min plus bad cert",
		l: &sigLayer{
			Layer: layer,
			desc: v1.Descriptor{
				Digest: digest,
				Annotations: map[string]string{
					sigkey:  "blah",
					certkey: `GARBAGE`,
				},
			},
		},
		wantSig:     "blah",
		wantCertErr: errors.New(`error during PEM decoding`),
	}, {
		name: "min plus bad chain",
		l: &sigLayer{
			Layer: layer,
			desc: v1.Descriptor{
				Digest: digest,
				Annotations: map[string]string{
					sigkey:   "blah",
					chainkey: `GARBAGE`,
				},
			},
		},
		wantSig:      "blah",
		wantChainErr: errors.New(`error during PEM decoding`),
	}, {
		name: "min plus bundle",
		l: &sigLayer{
			Layer: layer,
			desc: v1.Descriptor{
				Digest: digest,
				Annotations: map[string]string{
					sigkey: "blah",
					// This was extracted from gcr.io/distroless/static:nonroot on 2021/09/16.
					// The Body has been removed for brevity
					BundleKey: `{"SignedEntryTimestamp":"MEUCIQClUkUqZNf+6dxBc/pxq22JIluTB7Kmip1G0FIF5E0C1wIgLqXm+IM3JYW/P/qjMZSXW+J8bt5EOqNfe3R+0A9ooFE=","Payload":{"body":"REMOVED","integratedTime":1631646761,"logIndex":693591,"logID":"c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"}}`,
				},
			},
		},
		wantSig: "blah",
		wantBundle: &bundle.RekorBundle{
			SignedEntryTimestamp: mustDecode("MEUCIQClUkUqZNf+6dxBc/pxq22JIluTB7Kmip1G0FIF5E0C1wIgLqXm+IM3JYW/P/qjMZSXW+J8bt5EOqNfe3R+0A9ooFE="),
			Payload: bundle.RekorPayload{
				Body:           "REMOVED",
				IntegratedTime: 1631646761,
				LogIndex:       693591,
				LogID:          "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
			},
		},
	}, {
		name: "min plus timestamp",
		l: &sigLayer{
			Layer: layer,
			desc: v1.Descriptor{
				Digest: digest,
				Annotations: map[string]string{
					sigkey:       "blah",
					TimestampKey: `{"signatures":[{"keyid":"b6710623a30c010738e64c5209d367df1c0a18cf90e6ab5292fb01680f83453d","sig":"3046022100926cd1a5a90539f3efa97390293180132413c7d30d94399c220a8a9aa9907e6e0221009e07b0e207f76dd45caeab87258553ddcf83fc7db6dfbbd4678d18f8c3517023"}],"signed":{"_type":"timestamp","spec_version":"1.0","version":8,"expires":"2022-01-15T00:39:22Z","meta":{"snapshot.json":{"length":1658,"hashes":{"sha256":"95e5b6822e0c3a9924f2f906c0b75e09246ad6d37078806085a273fddd079679","sha512":"4b1df9f2cc2d052bee185554ded7c526e283d4fab8388557a7b684c4ce0efb28c196e33a5140e7de9de99b2f5f37a7b2503617c2ff220168c5b7a79340675acf"},"version":8}}}}`,
				},
			},
		},
		wantSig: "blah",
		wantTimestamp: &oci.Timestamp{
			Signatures: []data.Signature{
				{
					KeyID:     "b6710623a30c010738e64c5209d367df1c0a18cf90e6ab5292fb01680f83453d",
					Signature: []byte{48, 70, 2, 33, 0, 146, 108, 209, 165, 169, 5, 57, 243, 239, 169, 115, 144, 41, 49, 128, 19, 36, 19, 199, 211, 13, 148, 57, 156, 34, 10, 138, 154, 169, 144, 126, 110, 2, 33, 0, 158, 7, 176, 226, 7, 247, 109, 212, 92, 174, 171, 135, 37, 133, 83, 221, 207, 131, 252, 125, 182, 223, 187, 212, 103, 141, 24, 248, 195, 81, 112, 35},
				},
			},
			Signed: data.Timestamp{
				Type:        "timestamp",
				SpecVersion: "1.0",
				Version:     8,
				Expires:     ts,
				Meta: map[string]data.TimestampFileMeta{
					"snapshot.json": {
						FileMeta: data.FileMeta{
							Length: 1658,
							Hashes: map[string]data.HexBytes{
								"sha256": []byte{149, 229, 182, 130, 46, 12, 58, 153, 36, 242, 249, 6, 192, 183, 94, 9, 36, 106, 214, 211, 112, 120, 128, 96, 133, 162, 115, 253, 221, 7, 150, 121},
								"sha512": []byte{75, 29, 249, 242, 204, 45, 5, 43, 238, 24, 85, 84, 222, 215, 197, 38, 226, 131, 212, 250, 184, 56, 133, 87, 167, 182, 132, 196, 206, 14, 251, 40, 193, 150, 227, 58, 81, 64, 231, 222, 157, 233, 155, 47, 95, 55, 167, 178, 80, 54, 23, 194, 255, 34, 1, 104, 197, 183, 167, 147, 64, 103, 90, 207},
							},
						},
						Version: 8,
					},
				},
			},
		},
	}, {
		name: "min plus good cert",
		l: &sigLayer{
			Layer: layer,
			desc: v1.Descriptor{
				Digest: digest,
				Annotations: map[string]string{
					sigkey: "blah",
					// This was extracted from gcr.io/distroless/static:nonroot on 2021/09/16
					certkey: `
-----BEGIN CERTIFICATE-----
MIICjzCCAhSgAwIBAgITV2heiswW9YldtVEAu98QxDO8TTAKBggqhkjOPQQDAzAq
MRUwEwYDVQQKEwxzaWdzdG9yZS5kZXYxETAPBgNVBAMTCHNpZ3N0b3JlMB4XDTIx
MDkxNDE5MTI0MFoXDTIxMDkxNDE5MzIzOVowADBZMBMGByqGSM49AgEGCCqGSM49
AwEHA0IABMF1AWZcfvubslc4ABNnvGbRjm6GWVHxrJ1RRthTHMCE4FpFmiHQBfGt
6n80DqszGj77Whb35O33+Dal4Y2po+CjggFBMIIBPTAOBgNVHQ8BAf8EBAMCB4Aw
EwYDVR0lBAwwCgYIKwYBBQUHAwMwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU340G
3G1ozVNmFC5TBFV0yNuouvowHwYDVR0jBBgwFoAUyMUdAEGaJCkyUSTrDa5K7UoG
0+wwgY0GCCsGAQUFBwEBBIGAMH4wfAYIKwYBBQUHMAKGcGh0dHA6Ly9wcml2YXRl
Y2EtY29udGVudC02MDNmZTdlNy0wMDAwLTIyMjctYmY3NS1mNGY1ZTgwZDI5NTQu
c3RvcmFnZS5nb29nbGVhcGlzLmNvbS9jYTM2YTFlOTYyNDJiOWZjYjE0Ni9jYS5j
cnQwOAYDVR0RAQH/BC4wLIEqa2V5bGVzc0BkaXN0cm9sZXNzLmlhbS5nc2Vydmlj
ZWFjY291bnQuY29tMAoGCCqGSM49BAMDA2kAMGYCMQDcH9cdkxW6ugsbPHqX9qrM
wlMaprcwnlktS3+5xuABr5icuqwrB/Fj5doFtS7AnM0CMQD9MjSaUmHFFF7zoLMx
uThR1Z6JuA21HwxtL3GyJ8UQZcEPOlTBV593HrSAwBhiCoY=
-----END CERTIFICATE-----
`,
				},
			},
		},
		wantSig:  "blah",
		wantCert: true,
	}, {
		name: "min plus bad chain",
		l: &sigLayer{
			Layer: layer,
			desc: v1.Descriptor{
				Digest: digest,
				Annotations: map[string]string{
					sigkey: "blah",
					// This was extracted from gcr.io/distroless/static:nonroot on 2021/09/16
					chainkey: `
-----BEGIN CERTIFICATE-----
MIIB+DCCAX6gAwIBAgITNVkDZoCiofPDsy7dfm6geLbuhzAKBggqhkjOPQQDAzAq
MRUwEwYDVQQKEwxzaWdzdG9yZS5kZXYxETAPBgNVBAMTCHNpZ3N0b3JlMB4XDTIx
MDMwNzAzMjAyOVoXDTMxMDIyMzAzMjAyOVowKjEVMBMGA1UEChMMc2lnc3RvcmUu
ZGV2MREwDwYDVQQDEwhzaWdzdG9yZTB2MBAGByqGSM49AgEGBSuBBAAiA2IABLSy
A7Ii5k+pNO8ZEWY0ylemWDowOkNa3kL+GZE5Z5GWehL9/A9bRNA3RbrsZ5i0Jcas
taRL7Sp5fp/jD5dxqc/UdTVnlvS16an+2Yfswe/QuLolRUCrcOE2+2iA5+tzd6Nm
MGQwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwHQYDVR0OBBYE
FMjFHQBBmiQpMlEk6w2uSu1KBtPsMB8GA1UdIwQYMBaAFMjFHQBBmiQpMlEk6w2u
Su1KBtPsMAoGCCqGSM49BAMDA2gAMGUCMH8liWJfMui6vXXBhjDgY4MwslmN/TJx
Ve/83WrFomwmNf056y1X48F9c4m3a3ozXAIxAKjRay5/aj/jsKKGIkmQatjI8uup
Hr/+CxFvaJWmpYqNkLDGRU+9orzh5hI2RrcuaQ==
-----END CERTIFICATE-----
`,
				},
			},
		},
		wantSig:   "blah",
		wantChain: 1,
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			b, err := test.l.Payload()
			switch {
			case (err != nil) != (test.wantPayloadErr != nil):
				t.Errorf("Payload() = %v, wanted %v", err, test.wantPayloadErr)
			case (err != nil) && (test.wantPayloadErr != nil) && err.Error() != test.wantPayloadErr.Error():
				t.Errorf("Payload() = %v, wanted %v", err, test.wantPayloadErr)
			case err == nil:
				if got, _, err := v1.SHA256(bytes.NewBuffer(b)); err != nil {
					t.Errorf("v1.SHA256() = %v", err)
				} else if want := digest; want != got {
					t.Errorf("v1.SHA256() = %v, wanted %v", got, want)
				}
			}

			switch got, err := test.l.Base64Signature(); {
			case (err != nil) != (test.wantSigErr != nil):
				t.Errorf("Base64Signature() = %v, wanted %v", err, test.wantSigErr)
			case (err != nil) && (test.wantSigErr != nil) && err.Error() != test.wantSigErr.Error():
				t.Errorf("Base64Signature() = %v, wanted %v", err, test.wantSigErr)
			case got != test.wantSig:
				t.Errorf("Base64Signature() = %v, wanted %v", got, test.wantSig)
			}

			switch got, err := test.l.Cert(); {
			case (err != nil) != (test.wantCertErr != nil):
				t.Errorf("Cert() = %v, wanted %v", err, test.wantCertErr)
			case (err != nil) && (test.wantCertErr != nil) && err.Error() != test.wantCertErr.Error():
				t.Errorf("Cert() = %v, wanted %v", err, test.wantCertErr)
			case (got != nil) != test.wantCert:
				t.Errorf("Cert() = %v, wanted cert? %v", got, test.wantCert)
			}

			switch got, err := test.l.Chain(); {
			case (err != nil) != (test.wantChainErr != nil):
				t.Errorf("Chain() = %v, wanted %v", err, test.wantChainErr)
			case (err != nil) && (test.wantChainErr != nil) && err.Error() != test.wantChainErr.Error():
				t.Errorf("Chain() = %v, wanted %v", err, test.wantChainErr)
			case len(got) != test.wantChain:
				t.Errorf("Chain() = %v, wanted chain of length %d", got, test.wantChain)
			}

			switch got, err := test.l.Bundle(); {
			case (err != nil) != (test.wantBundleErr != nil):
				t.Errorf("Bundle() = %v, wanted %v", err, test.wantBundleErr)
			case (err != nil) && (test.wantBundleErr != nil) && err.Error() != test.wantBundleErr.Error():
				t.Errorf("Bundle() = %v, wanted %v", err, test.wantBundleErr)
			case !cmp.Equal(got, test.wantBundle):
				t.Errorf("Bundle() %s", cmp.Diff(got, test.wantBundle))
			}

			switch got, err := test.l.Timestamp(); {
			case (err != nil) != (test.wantTimestampErr != nil):
				t.Errorf("Timestamp() = %v, wanted %v", err, test.wantTimestampErr)
			case (err != nil) && (test.wantTimestampErr != nil) && err.Error() != test.wantTimestampErr.Error():
				t.Errorf("Timestamp() = %v, wanted %v", err, test.wantTimestampErr)
			case !cmp.Equal(got, test.wantTimestamp):
				t.Errorf("Timestamp() %s", cmp.Diff(got, test.wantTimestamp))
			}
		})
	}
}
