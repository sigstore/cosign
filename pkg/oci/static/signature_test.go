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

package static

import (
	"encoding/base64"
	"io"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/sigstore/cosign/v2/pkg/cosign/bundle"
)

func TestNewSignatureBasic(t *testing.T) {
	payload := "this is the content!"
	b64sig := "b64 content=="
	l, err := NewSignature([]byte(payload), b64sig, WithLayerMediaType("foo"))
	if err != nil {
		t.Fatalf("NewSignature() = %v", err)
	}

	t.Run("check size", func(t *testing.T) {
		wantSize := int64(len(payload))
		gotSize, err := l.Size()
		if err != nil {
			t.Fatalf("Size() = %v", err)
		}
		if gotSize != wantSize {
			t.Errorf("Size() = %d, wanted %d", gotSize, wantSize)
		}
	})

	t.Run("check media type", func(t *testing.T) {
		wantMT := types.MediaType("foo")
		gotMT, err := l.MediaType()
		if err != nil {
			t.Fatalf("MediaType() = %v", err)
		}
		if gotMT != wantMT {
			t.Errorf("MediaType() = %s, wanted %s", gotMT, wantMT)
		}
	})

	t.Run("check hashes", func(t *testing.T) {
		wantHash, _, err := v1.SHA256(strings.NewReader(payload))
		if err != nil {
			t.Fatalf("SHA256() = %v", err)
		}

		gotDigest, err := l.Digest()
		if err != nil {
			t.Fatalf("Digest() = %v", err)
		}
		if !cmp.Equal(gotDigest, wantHash) {
			t.Errorf("Digest = %s", cmp.Diff(gotDigest, wantHash))
		}

		gotDiffID, err := l.DiffID()
		if err != nil {
			t.Fatalf("DiffID() = %v", err)
		}
		if !cmp.Equal(gotDiffID, wantHash) {
			t.Errorf("DiffID = %s", cmp.Diff(gotDiffID, wantHash))
		}
	})

	t.Run("check content", func(t *testing.T) {
		comp, err := l.Compressed()
		if err != nil {
			t.Fatalf("Compressed() = %v", err)
		}
		defer comp.Close()
		compContent, err := io.ReadAll(comp)
		if err != nil {
			t.Fatalf("ReadAll() = %v", err)
		}
		if got, want := string(compContent), payload; got != want {
			t.Errorf("Compressed() = %s, wanted %s", got, want)
		}

		uncomp, err := l.Uncompressed()
		if err != nil {
			t.Fatalf("Uncompressed() = %v", err)
		}
		defer uncomp.Close()
		uncompContent, err := io.ReadAll(uncomp)
		if err != nil {
			t.Fatalf("ReadAll() = %v", err)
		}
		if got, want := string(uncompContent), payload; got != want {
			t.Errorf("Uncompressed() = %s, wanted %s", got, want)
		}

		gotPayload, err := l.Payload()
		if err != nil {
			t.Fatalf("Payload() = %v", err)
		}
		if got, want := string(gotPayload), payload; got != want {
			t.Errorf("Payload() = %s, wanted %s", got, want)
		}

		gotSig, err := l.Base64Signature()
		if err != nil {
			t.Fatalf("Base64Signature() = %v", err)
		}
		if got, want := gotSig, b64sig; got != want {
			t.Errorf("Base64Signature() = %s, wanted %s", got, want)
		}

		gotBundle, err := l.Bundle()
		if err != nil {
			t.Fatalf("Bundle() = %v", err)
		}
		if gotBundle != nil {
			t.Errorf("Bundle() = %#v, wanted nil", gotBundle)
		}
	})

	t.Run("check annotations", func(t *testing.T) {
		want := map[string]string{
			SignatureAnnotationKey: b64sig,
		}
		got, err := l.Annotations()
		if err != nil {
			t.Fatalf("Annotations() = %v", err)
		}
		if !cmp.Equal(got, want) {
			t.Errorf("Annotations = %s", cmp.Diff(got, want))
		}
	})

	t.Run("check signature accessors", func(t *testing.T) {
		gotPayload, err := l.Payload()
		if err != nil {
			t.Fatalf("Payload() = %v", err)
		}
		if got, want := string(gotPayload), payload; got != want {
			t.Errorf("Payload() = %s, wanted %s", got, want)
		}

		gotSig, err := l.Base64Signature()
		if err != nil {
			t.Fatalf("Base64Signature() = %v", err)
		}
		if got, want := gotSig, b64sig; got != want {
			t.Errorf("Base64Signature() = %s, wanted %s", got, want)
		}

		if got, err := l.Bundle(); err != nil {
			t.Fatalf("Bundle() = %v", err)
		} else if got != nil {
			t.Errorf("Bundle() = %#v, wanted nil", got)
		}

		if got, err := l.Cert(); err != nil {
			t.Fatalf("Cert() = %v", err)
		} else if got != nil {
			t.Errorf("Cert() = %#v, wanted nil", got)
		}

		if got, err := l.Chain(); err != nil {
			t.Fatalf("Chain() = %v", err)
		} else if len(got) != 0 {
			t.Errorf("len(Chain()) = %d, wanted 0", len(got))
		}
	})
}

func TestNewAttestationBasic(t *testing.T) {
	payload := "this is the content!"
	l, err := NewAttestation([]byte(payload), WithLayerMediaType("foo"))
	if err != nil {
		t.Fatalf("NewSignature() = %v", err)
	}

	t.Run("check size", func(t *testing.T) {
		wantSize := int64(len(payload))
		gotSize, err := l.Size()
		if err != nil {
			t.Fatalf("Size() = %v", err)
		}
		if gotSize != wantSize {
			t.Errorf("Size() = %d, wanted %d", gotSize, wantSize)
		}
	})

	t.Run("check media type", func(t *testing.T) {
		wantMT := types.MediaType("foo")
		gotMT, err := l.MediaType()
		if err != nil {
			t.Fatalf("MediaType() = %v", err)
		}
		if gotMT != wantMT {
			t.Errorf("MediaType() = %s, wanted %s", gotMT, wantMT)
		}
	})

	t.Run("check hashes", func(t *testing.T) {
		wantHash, _, err := v1.SHA256(strings.NewReader(payload))
		if err != nil {
			t.Fatalf("SHA256() = %v", err)
		}

		gotDigest, err := l.Digest()
		if err != nil {
			t.Fatalf("Digest() = %v", err)
		}
		if !cmp.Equal(gotDigest, wantHash) {
			t.Errorf("Digest = %s", cmp.Diff(gotDigest, wantHash))
		}

		gotDiffID, err := l.DiffID()
		if err != nil {
			t.Fatalf("DiffID() = %v", err)
		}
		if !cmp.Equal(gotDiffID, wantHash) {
			t.Errorf("DiffID = %s", cmp.Diff(gotDiffID, wantHash))
		}
	})

	t.Run("check content", func(t *testing.T) {
		comp, err := l.Compressed()
		if err != nil {
			t.Fatalf("Compressed() = %v", err)
		}
		defer comp.Close()
		compContent, err := io.ReadAll(comp)
		if err != nil {
			t.Fatalf("ReadAll() = %v", err)
		}
		if got, want := string(compContent), payload; got != want {
			t.Errorf("Compressed() = %s, wanted %s", got, want)
		}

		uncomp, err := l.Uncompressed()
		if err != nil {
			t.Fatalf("Uncompressed() = %v", err)
		}
		defer uncomp.Close()
		uncompContent, err := io.ReadAll(uncomp)
		if err != nil {
			t.Fatalf("ReadAll() = %v", err)
		}
		if got, want := string(uncompContent), payload; got != want {
			t.Errorf("Uncompressed() = %s, wanted %s", got, want)
		}

		gotPayload, err := l.Payload()
		if err != nil {
			t.Fatalf("Payload() = %v", err)
		}
		if got, want := string(gotPayload), payload; got != want {
			t.Errorf("Payload() = %s, wanted %s", got, want)
		}

		gotSig, err := l.Base64Signature()
		if err != nil {
			t.Fatalf("Base64Signature() = %v", err)
		}
		if got, want := gotSig, ""; got != want {
			t.Errorf("Base64Signature() = %s, wanted %s", got, want)
		}

		gotBundle, err := l.Bundle()
		if err != nil {
			t.Fatalf("Bundle() = %v", err)
		}
		if gotBundle != nil {
			t.Errorf("Bundle() = %#v, wanted nil", gotBundle)
		}
	})

	t.Run("check annotations", func(t *testing.T) {
		want := map[string]string{
			SignatureAnnotationKey: "",
		}
		got, err := l.Annotations()
		if err != nil {
			t.Fatalf("Annotations() = %v", err)
		}
		if !cmp.Equal(got, want) {
			t.Errorf("Annotations = %s", cmp.Diff(got, want))
		}
	})

	t.Run("check signature accessors", func(t *testing.T) {
		gotPayload, err := l.Payload()
		if err != nil {
			t.Fatalf("Payload() = %v", err)
		}
		if got, want := string(gotPayload), payload; got != want {
			t.Errorf("Payload() = %s, wanted %s", got, want)
		}

		gotSig, err := l.Base64Signature()
		if err != nil {
			t.Fatalf("Base64Signature() = %v", err)
		}
		if got, want := gotSig, ""; got != want {
			t.Errorf("Base64Signature() = %s, wanted %s", got, want)
		}

		if got, err := l.Bundle(); err != nil {
			t.Fatalf("Bundle() = %v", err)
		} else if got != nil {
			t.Errorf("Bundle() = %#v, wanted nil", got)
		}

		if got, err := l.Cert(); err != nil {
			t.Fatalf("Cert() = %v", err)
		} else if got != nil {
			t.Errorf("Cert() = %#v, wanted nil", got)
		}

		if got, err := l.Chain(); err != nil {
			t.Fatalf("Chain() = %v", err)
		} else if len(got) != 0 {
			t.Errorf("len(Chain()) = %d, wanted 0", len(got))
		}
	})
}

func TestNewSignatureCertChainAndBundle(t *testing.T) {
	payload := "this is the other content!"
	b64sig := "b64 content="

	// This was extracted from gcr.io/distroless/static:nonroot on 2021/09/16
	var (
		cert = []byte(`
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
		chain = []byte(`
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
		b = &bundle.RekorBundle{
			SignedEntryTimestamp: mustDecode("MEUCIQClUkUqZNf+6dxBc/pxq22JIluTB7Kmip1G0FIF5E0C1wIgLqXm+IM3JYW/P/qjMZSXW+J8bt5EOqNfe3R+0A9ooFE="),
			Payload: bundle.RekorPayload{
				Body:           "REMOVED",
				IntegratedTime: 1631646761,
				LogIndex:       693591,
				LogID:          "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
			},
		}
	)

	l, err := NewSignature([]byte(payload), b64sig,
		WithCertChain(cert, chain), WithBundle(b))
	if err != nil {
		t.Fatalf("NewSignature() = %v", err)
	}

	t.Run("check signature accessors", func(t *testing.T) {
		gotPayload, err := l.Payload()
		if err != nil {
			t.Fatalf("Payload() = %v", err)
		}
		if got, want := string(gotPayload), payload; got != want {
			t.Errorf("Payload() = %s, wanted %s", got, want)
		}

		gotSig, err := l.Base64Signature()
		if err != nil {
			t.Fatalf("Base64Signature() = %v", err)
		}
		if got, want := gotSig, b64sig; got != want {
			t.Errorf("Base64Signature() = %s, wanted %s", got, want)
		}

		if got, err := l.Bundle(); err != nil {
			t.Fatalf("Bundle() = %v", err)
		} else if got != b {
			t.Errorf("Bundle() = %#v, wanted %#v", got, b)
		}

		if got, err := l.Cert(); err != nil {
			t.Fatalf("Cert() = %v", err)
		} else if got == nil {
			t.Error("Cert() = nil, wanted non-nil")
		}

		if got, err := l.Chain(); err != nil {
			t.Fatalf("Chain() = %v", err)
		} else if len(got) != 1 {
			t.Errorf("len(Chain()) = %d, wanted 1", len(got))
		}
	})

	t.Run("check annotations", func(t *testing.T) {
		want := map[string]string{
			SignatureAnnotationKey:   b64sig,
			CertificateAnnotationKey: string(cert),
			ChainAnnotationKey:       string(chain),
			// This was extracted from gcr.io/distroless/static:nonroot on 2021/09/16.
			// The Body has been removed for brevity
			BundleAnnotationKey: `{"SignedEntryTimestamp":"MEUCIQClUkUqZNf+6dxBc/pxq22JIluTB7Kmip1G0FIF5E0C1wIgLqXm+IM3JYW/P/qjMZSXW+J8bt5EOqNfe3R+0A9ooFE=","Payload":{"body":"REMOVED","integratedTime":1631646761,"logIndex":693591,"logID":"c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"}}`,
		}
		got, err := l.Annotations()
		if err != nil {
			t.Fatalf("Annotations() = %v", err)
		}
		if !cmp.Equal(got, want) {
			t.Errorf("Annotations = %s", cmp.Diff(got, want))
		}
	})
}

func TestNewSignatureCertChainAndRekorRFC3161Timestamp(t *testing.T) {
	payload := "this is the other content!"
	b64sig := "b64 content="

	// This was extracted from gcr.io/distroless/static:nonroot on 2021/09/16
	var (
		cert = []byte(`
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
		chain = []byte(`
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
		b = &bundle.RFC3161Timestamp{
			SignedRFC3161Timestamp: mustDecode("MEUCIQClUkUqZNf+6dxBc/pxq22JIluTB7Kmip1G0FIF5E0C1wIgLqXm+IM3JYW/P/qjMZSXW+J8bt5EOqNfe3R+0A9ooFE="),
		}
		rekorBundle = &bundle.RekorBundle{
			SignedEntryTimestamp: mustDecode("MEUCIQClUkUqZNf+6dxBc/pxq22JIluTB7Kmip1G0FIF5E0C1wIgLqXm+IM3JYW/P/qjMZSXW+J8bt5EOqNfe3R+0A9ooFE="),
			Payload: bundle.RekorPayload{
				Body:           "REMOVED",
				IntegratedTime: 1631646761,
				LogIndex:       693591,
				LogID:          "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
			},
		}
	)

	l, err := NewSignature([]byte(payload), b64sig,
		WithCertChain(cert, chain), WithRFC3161Timestamp(b))
	if err != nil {
		t.Fatalf("NewSignature() = %v", err)
	}

	t.Run("check tsa signature accessors", func(t *testing.T) {
		gotPayload, err := l.Payload()
		if err != nil {
			t.Fatalf("Payload() = %v", err)
		}
		if got, want := string(gotPayload), payload; got != want {
			t.Errorf("Payload() = %s, wanted %s", got, want)
		}

		gotSig, err := l.Base64Signature()
		if err != nil {
			t.Fatalf("Base64Signature() = %v", err)
		}
		if got, want := gotSig, b64sig; got != want {
			t.Errorf("Base64Signature() = %s, wanted %s", got, want)
		}

		if got, err := l.RFC3161Timestamp(); err != nil {
			t.Fatalf("RFC3161Timestamp() = %v", err)
		} else if got != b {
			t.Errorf("RFC3161Timestamp() = %#v, wanted %#v", got, b)
		}

		if got, err := l.Cert(); err != nil {
			t.Fatalf("Cert() = %v", err)
		} else if got == nil {
			t.Error("Cert() = nil, wanted non-nil")
		}

		if got, err := l.Chain(); err != nil {
			t.Fatalf("Chain() = %v", err)
		} else if len(got) != 1 {
			t.Errorf("len(Chain()) = %d, wanted 1", len(got))
		}
	})

	t.Run("check tsa annotations", func(t *testing.T) {
		want := map[string]string{
			SignatureAnnotationKey:   b64sig,
			CertificateAnnotationKey: string(cert),
			ChainAnnotationKey:       string(chain),

			RFC3161TimestampAnnotationKey: `{"SignedRFC3161Timestamp":"MEUCIQClUkUqZNf+6dxBc/pxq22JIluTB7Kmip1G0FIF5E0C1wIgLqXm+IM3JYW/P/qjMZSXW+J8bt5EOqNfe3R+0A9ooFE="}`,
		}
		got, err := l.Annotations()
		if err != nil {
			t.Fatalf("Annotations() = %v", err)
		}
		if !cmp.Equal(got, want) {
			t.Errorf("Annotations = %s", cmp.Diff(got, want))
		}
	})

	newSig, err := NewSignature([]byte(payload), b64sig,
		WithCertChain(cert, chain), WithRFC3161Timestamp(b), WithBundle(rekorBundle))
	if err != nil {
		t.Fatalf("NewSignature() = %v", err)
	}

	t.Run("check signature accessors", func(t *testing.T) {
		gotPayload, err := newSig.Payload()
		if err != nil {
			t.Fatalf("Payload() = %v", err)
		}
		if got, want := string(gotPayload), payload; got != want {
			t.Errorf("Payload() = %s, wanted %s", got, want)
		}

		gotSig, err := newSig.Base64Signature()
		if err != nil {
			t.Fatalf("Base64Signature() = %v", err)
		}
		if got, want := gotSig, b64sig; got != want {
			t.Errorf("Base64Signature() = %s, wanted %s", got, want)
		}

		if got, err := newSig.Bundle(); err != nil {
			t.Fatalf("Bundle() = %v", err)
		} else if got != rekorBundle {
			t.Errorf("Bundle() = %#v, wanted %#v", got, b)
		}

		if got, err := newSig.RFC3161Timestamp(); err != nil {
			t.Fatalf("RFC3161Timestamp() = %v", err)
		} else if got != b {
			t.Errorf("RFC3161Timestamp() = %#v, wanted %#v", got, b)
		}

		if got, err := newSig.Cert(); err != nil {
			t.Fatalf("Cert() = %v", err)
		} else if got == nil {
			t.Error("Cert() = nil, wanted non-nil")
		}

		if got, err := newSig.Chain(); err != nil {
			t.Fatalf("Chain() = %v", err)
		} else if len(got) != 1 {
			t.Errorf("len(Chain()) = %d, wanted 1", len(got))
		}
	})

	t.Run("check rekor and tsa annotations", func(t *testing.T) {
		want := map[string]string{
			SignatureAnnotationKey:   b64sig,
			CertificateAnnotationKey: string(cert),
			ChainAnnotationKey:       string(chain),

			RFC3161TimestampAnnotationKey: `{"SignedRFC3161Timestamp":"MEUCIQClUkUqZNf+6dxBc/pxq22JIluTB7Kmip1G0FIF5E0C1wIgLqXm+IM3JYW/P/qjMZSXW+J8bt5EOqNfe3R+0A9ooFE="}`,
			BundleAnnotationKey:           `{"SignedEntryTimestamp":"MEUCIQClUkUqZNf+6dxBc/pxq22JIluTB7Kmip1G0FIF5E0C1wIgLqXm+IM3JYW/P/qjMZSXW+J8bt5EOqNfe3R+0A9ooFE=","Payload":{"body":"REMOVED","integratedTime":1631646761,"logIndex":693591,"logID":"c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"}}`,
		}
		got, err := newSig.Annotations()
		if err != nil {
			t.Fatalf("Annotations() = %v", err)
		}
		if !cmp.Equal(got, want) {
			t.Errorf("Annotations = %s", cmp.Diff(got, want))
		}
	})
}

func TestNewSignatureBadCertChain(t *testing.T) {
	payload := "this is the other content!"
	b64sig := "b64 content="

	// This was extracted from gcr.io/distroless/static:nonroot on 2021/09/16
	var (
		cert = []byte(`
-----BEGIN CERTIFICATE-----
garbage in
-----END CERTIFICATE-----
`)
		chain = []byte(`
-----BEGIN CERTIFICATE-----
garbage out
-----END CERTIFICATE-----
`)
	)

	l, err := NewSignature([]byte(payload), b64sig,
		WithCertChain(cert, chain))
	if err != nil {
		t.Fatalf("NewSignature() = %v", err)
	}

	t.Run("check signature accessors", func(t *testing.T) {
		if got, err := l.Cert(); err == nil {
			t.Fatalf("Cert() = %#v, wanted error", got)
		}

		if got, err := l.Chain(); err == nil {
			t.Fatalf("Chain() = %#v, wanted error", got)
		}
	})
}

func mustDecode(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err.Error())
	}
	return b
}
