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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"github.com/go-openapi/strfmt"
	"github.com/google/go-cmp/cmp"
	"github.com/sigstore/cosign/pkg/oci"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

const (
	testCertPEM = `-----BEGIN CERTIFICATE-----
MIICyTCCAlCgAwIBAgITYZXhosLz4+Q/XCUwBySVDmU2jTAKBggqhkjOPQQDAzAq
MRUwEwYDVQQKEwxzaWdzdG9yZS5kZXYxETAPBgNVBAMTCHNpZ3N0b3JlMB4XDTIx
MDMwOTA0NDYwOVoXDTIxMDMwOTA1MDYwMlowOjEbMBkGA1UECgwSbG9yZW5jLmRA
Z21haWwuY29tMRswGQYDVQQDDBJsb3JlbmMuZEBnbWFpbC5jb20wdjAQBgcqhkjO
PQIBBgUrgQQAIgNiAARIA8thgk3Zext2UWP1aBE1uoIAqetevPiEDuGKtSUPYxBv
AhzrwhDTbHrj6vMQCBNE7o4AfewyJAZf6CKbee8WIakPfAjRSTQjjnZBzKvSHn4K
u8SByXjFN0rde8qDqo+jggEmMIIBIjAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAww
CgYIKwYBBQUHAwMwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUQeDktDb9QFrYxF8H
xBXkAHQmvqwwHwYDVR0jBBgwFoAUyMUdAEGaJCkyUSTrDa5K7UoG0+wwgY0GCCsG
AQUFBwEBBIGAMH4wfAYIKwYBBQUHMAKGcGh0dHA6Ly9wcml2YXRlY2EtY29udGVu
dC02MDNmZTdlNy0wMDAwLTIyMjctYmY3NS1mNGY1ZTgwZDI5NTQuc3RvcmFnZS5n
b29nbGVhcGlzLmNvbS9jYTM2YTFlOTYyNDJiOWZjYjE0Ni9jYS5jcnQwHQYDVR0R
BBYwFIESbG9yZW5jLmRAZ21haWwuY29tMAoGCCqGSM49BAMDA2cAMGQCMAgjOcjN
P3w/xB8bi/hKXJ9RdNH/DMADiusGtd1d/xxyFVj1xYosQ7y1G6y84VDBvQIwMfQG
8Tp8zsxDg5Oz4qUBZ/AKmkPJHhgmiHftwbb5I1S+1xdhzJtJ8Eg0M00/nqok
-----END CERTIFICATE-----
`
)

var testCert = &x509.Certificate{
	Raw: []byte{0x30, 0x82, 0x2, 0xc9, 0x30, 0x82, 0x2, 0x50, 0xa0, 0x3, 0x2, 0x1, 0x2, 0x2, 0x13, 0x61, 0x95, 0xe1, 0xa2, 0xc2, 0xf3, 0xe3, 0xe4, 0x3f, 0x5c, 0x25, 0x30, 0x7, 0x24, 0x95, 0xe, 0x65, 0x36, 0x8d, 0x30, 0xa, 0x6, 0x8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x4, 0x3, 0x3, 0x30, 0x2a, 0x31, 0x15, 0x30, 0x13, 0x6, 0x3, 0x55, 0x4, 0xa, 0x13, 0xc, 0x73, 0x69, 0x67, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x64, 0x65, 0x76, 0x31, 0x11, 0x30, 0xf, 0x6, 0x3, 0x55, 0x4, 0x3, 0x13, 0x8, 0x73, 0x69, 0x67, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x30, 0x1e, 0x17, 0xd, 0x32, 0x31, 0x30, 0x33, 0x30, 0x39, 0x30, 0x34, 0x34, 0x36, 0x30, 0x39, 0x5a, 0x17, 0xd, 0x32, 0x31, 0x30, 0x33, 0x30, 0x39, 0x30, 0x35, 0x30, 0x36, 0x30, 0x32, 0x5a, 0x30, 0x3a, 0x31, 0x1b, 0x30, 0x19, 0x6, 0x3, 0x55, 0x4, 0xa, 0xc, 0x12, 0x6c, 0x6f, 0x72, 0x65, 0x6e, 0x63, 0x2e, 0x64, 0x40, 0x67, 0x6d, 0x61, 0x69, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x31, 0x1b, 0x30, 0x19, 0x6, 0x3, 0x55, 0x4, 0x3, 0xc, 0x12, 0x6c, 0x6f, 0x72, 0x65, 0x6e, 0x63, 0x2e, 0x64, 0x40, 0x67, 0x6d, 0x61, 0x69, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x76, 0x30, 0x10, 0x6, 0x7, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x2, 0x1, 0x6, 0x5, 0x2b, 0x81, 0x4, 0x0, 0x22, 0x3, 0x62, 0x0, 0x4, 0x48, 0x3, 0xcb, 0x61, 0x82, 0x4d, 0xd9, 0x7b, 0x1b, 0x76, 0x51, 0x63, 0xf5, 0x68, 0x11, 0x35, 0xba, 0x82, 0x0, 0xa9, 0xeb, 0x5e, 0xbc, 0xf8, 0x84, 0xe, 0xe1, 0x8a, 0xb5, 0x25, 0xf, 0x63, 0x10, 0x6f, 0x2, 0x1c, 0xeb, 0xc2, 0x10, 0xd3, 0x6c, 0x7a, 0xe3, 0xea, 0xf3, 0x10, 0x8, 0x13, 0x44, 0xee, 0x8e, 0x0, 0x7d, 0xec, 0x32, 0x24, 0x6, 0x5f, 0xe8, 0x22, 0x9b, 0x79, 0xef, 0x16, 0x21, 0xa9, 0xf, 0x7c, 0x8, 0xd1, 0x49, 0x34, 0x23, 0x8e, 0x76, 0x41, 0xcc, 0xab, 0xd2, 0x1e, 0x7e, 0xa, 0xbb, 0xc4, 0x81, 0xc9, 0x78, 0xc5, 0x37, 0x4a, 0xdd, 0x7b, 0xca, 0x83, 0xaa, 0x8f, 0xa3, 0x82, 0x1, 0x26, 0x30, 0x82, 0x1, 0x22, 0x30, 0xe, 0x6, 0x3, 0x55, 0x1d, 0xf, 0x1, 0x1, 0xff, 0x4, 0x4, 0x3, 0x2, 0x7, 0x80, 0x30, 0x13, 0x6, 0x3, 0x55, 0x1d, 0x25, 0x4, 0xc, 0x30, 0xa, 0x6, 0x8, 0x2b, 0x6, 0x1, 0x5, 0x5, 0x7, 0x3, 0x3, 0x30, 0xc, 0x6, 0x3, 0x55, 0x1d, 0x13, 0x1, 0x1, 0xff, 0x4, 0x2, 0x30, 0x0, 0x30, 0x1d, 0x6, 0x3, 0x55, 0x1d, 0xe, 0x4, 0x16, 0x4, 0x14, 0x41, 0xe0, 0xe4, 0xb4, 0x36, 0xfd, 0x40, 0x5a, 0xd8, 0xc4, 0x5f, 0x7, 0xc4, 0x15, 0xe4, 0x0, 0x74, 0x26, 0xbe, 0xac, 0x30, 0x1f, 0x6, 0x3, 0x55, 0x1d, 0x23, 0x4, 0x18, 0x30, 0x16, 0x80, 0x14, 0xc8, 0xc5, 0x1d, 0x0, 0x41, 0x9a, 0x24, 0x29, 0x32, 0x51, 0x24, 0xeb, 0xd, 0xae, 0x4a, 0xed, 0x4a, 0x6, 0xd3, 0xec, 0x30, 0x81, 0x8d, 0x6, 0x8, 0x2b, 0x6, 0x1, 0x5, 0x5, 0x7, 0x1, 0x1, 0x4, 0x81, 0x80, 0x30, 0x7e, 0x30, 0x7c, 0x6, 0x8, 0x2b, 0x6, 0x1, 0x5, 0x5, 0x7, 0x30, 0x2, 0x86, 0x70, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x63, 0x61, 0x2d, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x36, 0x30, 0x33, 0x66, 0x65, 0x37, 0x65, 0x37, 0x2d, 0x30, 0x30, 0x30, 0x30, 0x2d, 0x32, 0x32, 0x32, 0x37, 0x2d, 0x62, 0x66, 0x37, 0x35, 0x2d, 0x66, 0x34, 0x66, 0x35, 0x65, 0x38, 0x30, 0x64, 0x32, 0x39, 0x35, 0x34, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x61, 0x70, 0x69, 0x73, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x63, 0x61, 0x33, 0x36, 0x61, 0x31, 0x65, 0x39, 0x36, 0x32, 0x34, 0x32, 0x62, 0x39, 0x66, 0x63, 0x62, 0x31, 0x34, 0x36, 0x2f, 0x63, 0x61, 0x2e, 0x63, 0x72, 0x74, 0x30, 0x1d, 0x6, 0x3, 0x55, 0x1d, 0x11, 0x4, 0x16, 0x30, 0x14, 0x81, 0x12, 0x6c, 0x6f, 0x72, 0x65, 0x6e, 0x63, 0x2e, 0x64, 0x40, 0x67, 0x6d, 0x61, 0x69, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0xa, 0x6, 0x8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x4, 0x3, 0x3, 0x3, 0x67, 0x0, 0x30, 0x64, 0x2, 0x30, 0x8, 0x23, 0x39, 0xc8, 0xcd, 0x3f, 0x7c, 0x3f, 0xc4, 0x1f, 0x1b, 0x8b, 0xf8, 0x4a, 0x5c, 0x9f, 0x51, 0x74, 0xd1, 0xff, 0xc, 0xc0, 0x3, 0x8a, 0xeb, 0x6, 0xb5, 0xdd, 0x5d, 0xff, 0x1c, 0x72, 0x15, 0x58, 0xf5, 0xc5, 0x8a, 0x2c, 0x43, 0xbc, 0xb5, 0x1b, 0xac, 0xbc, 0xe1, 0x50, 0xc1, 0xbd, 0x2, 0x30, 0x31, 0xf4, 0x6, 0xf1, 0x3a, 0x7c, 0xce, 0xcc, 0x43, 0x83, 0x93, 0xb3, 0xe2, 0xa5, 0x1, 0x67, 0xf0, 0xa, 0x9a, 0x43, 0xc9, 0x1e, 0x18, 0x26, 0x88, 0x77, 0xed, 0xc1, 0xb6, 0xf9, 0x23, 0x54, 0xbe, 0xd7, 0x17, 0x61, 0xcc, 0x9b, 0x49, 0xf0, 0x48, 0x34, 0x33, 0x4d, 0x3f, 0x9e, 0xaa, 0x24},
}

func TestRekorbytes(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("could not generate key: %v", err)
	}
	testPub := &key.PublicKey
	testPubPEM, err := cryptoutils.MarshalPublicKeyToPEM(testPub)
	if err != nil {
		t.Fatalf("could not marshall public key to PEM: %v", err)
	}

	testCases := []struct {
		desc string

		cert *x509.Certificate
		pub  crypto.PublicKey

		expected []byte
	}{
		{
			desc: "cert only",

			cert:     testCert,
			expected: []byte(testCertPEM),
		},
		{
			desc: "pub only",

			pub:      testPub,
			expected: testPubPEM,
		},
		{
			desc: "pub and cert",

			cert:     testCert,
			pub:      testPub,
			expected: []byte(testCertPEM),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			result, err := rekorBytes(tc.cert, tc.pub)
			if err != nil {
				t.Fatalf("rekorBytes returned error: %v", err)
			}

			if !bytes.Equal(result, tc.expected) {
				t.Errorf("rekorBytes returned %q, wanted %q", string(result), string(tc.expected))
			}
		})
	}
}

func TestBundle(t *testing.T) {
	testEntryTime := int64(1234567890)
	testLogIndex := int64(55555)
	testLogID := "test log ID"
	testBody := "test body"

	testEntry := &models.LogEntryAnon{
		IntegratedTime: &testEntryTime,
		Body:           testBody,
		LogIndex:       &testLogIndex,
		LogID:          &testLogID,
	}

	t.Run("no verification", func(t *testing.T) {
		result := bundle(testEntry)
		if result != nil {
			t.Errorf("bundle() returned %v, wanted `nil`", result)
		}
	})

	testSET := strfmt.Base64([]byte{0x05, 0x04, 0x03, 0x02, 0x01})

	testVerification := &models.LogEntryAnonVerification{
		SignedEntryTimestamp: testSET,
	}
	testEntry.Verification = testVerification

	expected := &oci.Bundle{
		SignedEntryTimestamp: testSET,
		Payload: oci.BundlePayload{
			IntegratedTime: testEntryTime,
			Body:           testBody,
			LogIndex:       testLogIndex,
			LogID:          testLogID,
		},
	}

	t.Run("happy case", func(t *testing.T) {
		result := bundle(testEntry)
		if d := cmp.Diff(expected, result); d != "" {
			t.Errorf("bundle() returned unexpected result (-want +got): %s", d)
		}
	})
}
