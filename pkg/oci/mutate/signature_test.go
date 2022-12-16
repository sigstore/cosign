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

package mutate

import (
	"encoding/base64"
	"io"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
)

var (
	testCertBytes = []byte(`
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
`)
	testChainBytes = []byte(`
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
`)
)

func mustCreateSignature(t *testing.T, payload []byte, b64sig string, opts ...static.Option) oci.Signature {
	t.Helper()
	sig, err := static.NewSignature(payload, b64sig, opts...)
	if err != nil {
		t.Fatalf("failed to create static signature: %v", err)
	}
	return sig
}

func mustBase64Decode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("failed to base64 decode: %v", err)
	}
	return b
}

func assertSignaturesEqual(t *testing.T, wanted, got oci.Signature) {
	t.Helper()

	t.Run("Payloads match", func(t *testing.T) {
		t.Helper()
		wantedPayload, err := wanted.Payload()
		if err != nil {
			t.Fatalf("wanted.Payload() returned error: %v", err)
		}
		gotPayload, err := got.Payload()
		if err != nil {
			t.Fatalf("got.Payload() returned error: %v", err)
		}
		if diff := cmp.Diff(wantedPayload, gotPayload); diff != "" {
			t.Errorf("Payload() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("Base64Signatures match", func(t *testing.T) {
		t.Helper()
		wantedB64Sig, err := wanted.Base64Signature()
		if err != nil {
			t.Fatalf("wanted.Base64Signature() returned error: %v", err)
		}
		gotB64Sig, err := got.Base64Signature()
		if err != nil {
			t.Fatalf("got.Base64Signature() returned error: %v", err)
		}
		if diff := cmp.Diff(wantedB64Sig, gotB64Sig); diff != "" {
			t.Errorf("Base64Signature() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("Bundles match", func(t *testing.T) {
		t.Helper()
		wantedBundle, err := wanted.Bundle()
		if err != nil {
			t.Fatalf("wanted.Bundle() returned error: %v", err)
		}
		gotBundle, err := got.Bundle()
		if err != nil {
			t.Fatalf("got.Bundle() returned error: %v", err)
		}
		if diff := cmp.Diff(wantedBundle, gotBundle); diff != "" {
			t.Errorf("Bundle() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("RFC3161 timestamp bundles match", func(t *testing.T) {
		t.Helper()
		wantedBundle, err := wanted.RFC3161Timestamp()
		if err != nil {
			t.Fatalf("wanted.Bundle() returned error: %v", err)
		}
		gotBundle, err := got.RFC3161Timestamp()
		if err != nil {
			t.Fatalf("got.RFC3161Timestamp() returned error: %v", err)
		}
		if diff := cmp.Diff(wantedBundle, gotBundle); diff != "" {
			t.Errorf("RFC3161Timestamp() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("Certs match", func(t *testing.T) {
		t.Helper()
		wantedCert, err := wanted.Cert()
		if err != nil {
			t.Fatalf("wanted.Bundle() returned error: %v", err)
		}
		gotCert, err := got.Cert()
		if err != nil {
			t.Fatalf("got.Cert() returned error: %v", err)
		}
		if diff := cmp.Diff(wantedCert, gotCert); diff != "" {
			t.Errorf("Cert() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("Chains match", func(t *testing.T) {
		t.Helper()
		wantedChain, err := wanted.Chain()
		if err != nil {
			t.Fatalf("wanted.Bundle() returned error: %v", err)
		}
		gotChain, err := got.Chain()
		if err != nil {
			t.Fatalf("got.Chain() returned error: %v", err)
		}
		if diff := cmp.Diff(wantedChain, gotChain); diff != "" {
			t.Errorf("Chain() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("MediaTypes match", func(t *testing.T) {
		t.Helper()
		wantedMediaType, err := wanted.MediaType()
		if err != nil {
			t.Fatalf("wanted.MediaType() returned error: %v", err)
		}
		gotMediaType, err := got.MediaType()
		if err != nil {
			t.Fatalf("got.MediaType() returned error: %v", err)
		}
		if diff := cmp.Diff(wantedMediaType, gotMediaType); diff != "" {
			t.Errorf("MediaType() mismatch (-want +got):\n%s", diff)
		}
	})

	var gotAnnotations map[string]string
	t.Run("Annotations match", func(t *testing.T) {
		t.Helper()
		wantedAnnotations, err := wanted.Annotations()
		if err != nil {
			t.Fatalf("wanted.Annotations() returned error: %v", err)
		}
		gotAnnotations, err = got.Annotations()
		if err != nil {
			t.Fatalf("got.Annotations() returned error: %v", err)
		}
		if diff := cmp.Diff(wantedAnnotations, gotAnnotations); diff != "" {
			t.Errorf("Annotations() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("DiffIDs match", func(t *testing.T) {
		t.Helper()
		wantedDiffID, err := wanted.DiffID()
		if err != nil {
			t.Fatalf("wanted.DiffID() returned error: %v", err)
		}
		gotDiffID, err := got.DiffID()
		if err != nil {
			t.Fatalf("got.DiffID() returned error: %v", err)
		}
		if wantedDiffID != gotDiffID {
			t.Errorf("DiffID() mismatch. Wanted: %v, got: %v", wantedDiffID, gotDiffID)
		}
	})

	t.Run("Sizes match", func(t *testing.T) {
		t.Helper()
		wantedSize, err := wanted.Size()
		if err != nil {
			t.Fatalf("wanted.Size() returned error: %v", err)
		}
		gotSize, err := got.Size()
		if err != nil {
			t.Fatalf("got.Size() returned error: %v", err)
		}
		if wantedSize != gotSize {
			t.Errorf("Size() mismatch. Wanted: %v, got: %v", wantedSize, gotSize)
		}
	})

	t.Run("Compressed values match", func(t *testing.T) {
		t.Helper()
		wantedCompReader, err := wanted.Compressed()
		if err != nil {
			t.Fatalf("wanted.Compressed() returned error: %v", err)
		}
		defer wantedCompReader.Close()
		wantedCompressed, err := io.ReadAll(wantedCompReader)
		if err != nil {
			t.Fatalf("io.ReadAll(wanted.Compressed()) returned error: %v", err)
		}
		gotCompReader, err := got.Compressed()
		if err != nil {
			t.Fatalf("got.Compressed() returned error: %v", err)
		}
		defer gotCompReader.Close()
		gotCompressed, err := io.ReadAll(gotCompReader)
		if err != nil {
			t.Fatalf("io.ReadAll(got.Compressed()) returned error: %v", err)
		}
		if diff := cmp.Diff(wantedCompressed, gotCompressed); diff != "" {
			t.Errorf("MediaType() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("Uncompressed values match", func(t *testing.T) {
		t.Helper()
		wantedUncompReader, err := wanted.Uncompressed()
		if err != nil {
			t.Fatalf("wanted.Uncompressed() returned error: %v", err)
		}
		defer wantedUncompReader.Close()
		wantedUncompressed, err := io.ReadAll(wantedUncompReader)
		if err != nil {
			t.Fatalf("io.ReadAll(wanted.Uncompressed()) returned error: %v", err)
		}
		gotUncompReader, err := got.Uncompressed()
		if err != nil {
			t.Fatalf("got.Compressed() returned error: %v", err)
		}
		defer gotUncompReader.Close()
		gotUncompressed, err := io.ReadAll(gotUncompReader)
		if err != nil {
			t.Fatalf("io.ReadAll(got.Uncompressed()) returned error: %v", err)
		}
		if diff := cmp.Diff(wantedUncompressed, gotUncompressed); diff != "" {
			t.Errorf("MediaType() mismatch (-want +got):\n%s", diff)
		}
	})
}

func TestSignatureWithAnnotations(t *testing.T) {
	payload := "this is the TestSignatureWithAnnotations content!"
	b64sig := "b64 content1="
	annotations := map[string]string{
		"foo":  "bar",
		"test": "yes",
	}
	originalSig := mustCreateSignature(t, []byte(payload), b64sig)
	expectedSig := mustCreateSignature(t, []byte(payload), b64sig, static.WithAnnotations(annotations))

	newSig, err := Signature(originalSig, WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("Signature(WithAnnotations()) returned error: %v", err)
	}

	assertSignaturesEqual(t, expectedSig, newSig)
}

func TestSignatureWithBundle(t *testing.T) {
	payload := "this is the TestSignatureWithBundle content!"
	b64sig := "b64 content2="
	b := &bundle.RekorBundle{
		SignedEntryTimestamp: mustBase64Decode(t, "MEUCIEDcarEwRYkrxE9ne+kzEVvUhnWaauYzxhUyXOLy1hwAAiEA4VdVCvNRs+D/5o33C2KBy+q2YX3lP4Y7nqRFU+K3hi0="),
		Payload: bundle.RekorPayload{
			Body:           "REMOVED",
			IntegratedTime: 1631646761,
			LogIndex:       693591,
			LogID:          "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
		},
	}
	originalSig := mustCreateSignature(t, []byte(payload), b64sig)
	expectedSig := mustCreateSignature(t, []byte(payload), b64sig, static.WithBundle(b))

	newSig, err := Signature(originalSig, WithBundle(b))
	if err != nil {
		t.Fatalf("Signature(WithBundle()) returned error: %v", err)
	}

	assertSignaturesEqual(t, expectedSig, newSig)
}

func TestSignatureWithRFC3161Timestamp(t *testing.T) {
	payload := "this is the TestSignatureWithBundle content!"
	b64sig := "b64 content2="
	b := &bundle.RFC3161Timestamp{
		SignedRFC3161Timestamp: mustBase64Decode(t, "MEUCIQClUkUqZNf+6dxBc/pxq22JIluTB7Kmip1G0FIF5E0C1wIgLqXm+IM3JYW/P/qjMZSXW+J8bt5EOqNfe3R+0A9ooFE="),
	}
	originalSig := mustCreateSignature(t, []byte(payload), b64sig)
	expectedSig := mustCreateSignature(t, []byte(payload), b64sig, static.WithRFC3161Timestamp(b))

	newSig, err := Signature(originalSig, WithRFC3161Timestamp(b))
	if err != nil {
		t.Fatalf("Signature(WithRFC3161Timestamp()) returned error: %v", err)
	}

	assertSignaturesEqual(t, expectedSig, newSig)
}

func TestSignatureWithCertChain(t *testing.T) {
	payload := "this is the TestSignatureWithCertChain content!"
	b64sig := "b64 content3="

	originalSig := mustCreateSignature(t, []byte(payload), b64sig)
	expectedSig := mustCreateSignature(t, []byte(payload), b64sig, static.WithCertChain(testCertBytes, testChainBytes))

	newSig, err := Signature(originalSig, WithCertChain(testCertBytes, testChainBytes))
	if err != nil {
		t.Fatalf("Signature(WithCertChain()) returned error: %v", err)
	}

	assertSignaturesEqual(t, expectedSig, newSig)
}

func TestSignatureWithMediaType(t *testing.T) {
	payload := "this is the TestSignatureWithMediaType content!"
	b64sig := "b64 content4="
	mediaType := types.MediaType("test/media.type")

	originalSig := mustCreateSignature(t, []byte(payload), b64sig)
	expectedSig := mustCreateSignature(t, []byte(payload), b64sig, static.WithLayerMediaType(mediaType))

	newSig, err := Signature(originalSig, WithMediaType(mediaType))
	if err != nil {
		t.Fatalf("Signature(WithMediaType()) returned error: %v", err)
	}

	assertSignaturesEqual(t, expectedSig, newSig)
}

func TestSignatureWithEverything(t *testing.T) {
	payload := "this is the TestSignatureWithEverything content!"
	b64sig := "b64 content5="
	annotations := map[string]string{
		"foo":  "bar",
		"test": "yes",
	}
	b := &bundle.RekorBundle{
		SignedEntryTimestamp: mustBase64Decode(t, "MEUCIQClUkUqZNf+6dxBc/pxq22JIluTB7Kmip1G0FIF5E0C1wIgLqXm+IM3JYW/P/qjMZSXW+J8bt5EOqNfe3R+0A9ooFE="),
		Payload: bundle.RekorPayload{
			Body:           "REMOVED",
			IntegratedTime: 1631646761,
			LogIndex:       693591,
			LogID:          "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
		},
	}
	mediaType := types.MediaType("test/media.type")

	originalSig := mustCreateSignature(t, []byte(payload), b64sig)

	expectedSig := mustCreateSignature(t, []byte(payload), b64sig,
		static.WithAnnotations(annotations),
		static.WithBundle(b),
		static.WithCertChain(testCertBytes, testChainBytes),
		static.WithLayerMediaType(mediaType))

	newSig, err := Signature(originalSig,
		WithAnnotations(annotations),
		WithBundle(b),
		WithCertChain(testCertBytes, testChainBytes),
		WithMediaType(mediaType))

	if err != nil {
		t.Fatalf("Signature(With...) returned error: %v", err)
	}

	assertSignaturesEqual(t, expectedSig, newSig)
}

func TestSignatureWithEverythingTSA(t *testing.T) {
	payload := "this is the TestSignatureWithEverything content!"
	b64sig := "b64 content5="
	annotations := map[string]string{
		"foo":  "bar",
		"test": "yes",
	}
	b := &bundle.RFC3161Timestamp{
		SignedRFC3161Timestamp: mustBase64Decode(t, "MEUCIQClUkUqZNf+6dxBc/pxq22JIluTB7Kmip1G0FIF5E0C1wIgLqXm+IM3JYW/P/qjMZSXW+J8bt5EOqNfe3R+0A9ooFE="),
	}
	mediaType := types.MediaType("test/media.type")

	originalSig := mustCreateSignature(t, []byte(payload), b64sig)

	expectedSig := mustCreateSignature(t, []byte(payload), b64sig,
		static.WithAnnotations(annotations),
		static.WithRFC3161Timestamp(b),
		static.WithCertChain(testCertBytes, testChainBytes),
		static.WithLayerMediaType(mediaType))

	newSig, err := Signature(originalSig,
		WithAnnotations(annotations),
		WithRFC3161Timestamp(b),
		WithCertChain(testCertBytes, testChainBytes),
		WithMediaType(mediaType))

	if err != nil {
		t.Fatalf("Signature(With...) returned error: %v", err)
	}

	assertSignaturesEqual(t, expectedSig, newSig)
}
