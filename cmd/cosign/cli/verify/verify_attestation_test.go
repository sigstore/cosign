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

package verify

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/sigstore/cosign/v3/pkg/oci/signed"
	"github.com/sigstore/cosign/v3/pkg/oci/static"
	"github.com/sigstore/cosign/v3/pkg/types"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	sigdsse "github.com/sigstore/sigstore/pkg/signature/dsse"
	"github.com/stretchr/testify/require"
)

func TestVerifyAttestationExperimentalOCI11(t *testing.T) {
	t.Setenv("COSIGN_REPOSITORY", "")
	s := httptest.NewServer(registry.New(registry.WithReferrersSupport(true)))
	defer s.Close()
	ref, err := name.NewTag(strings.TrimPrefix(s.URL, "http://") + "/repo:signed")
	require.NoError(t, err)
	rOpts := []remote.Option{
		remote.WithTransport(s.Client().Transport),
		remote.WithAuth(authn.Anonymous),
	}
	img, err := random.Image(100, 1)
	require.NoError(t, err)
	require.NoError(t, remote.Write(ref, img, rOpts...))
	h, err := img.Digest()
	require.NoError(t, err)
	digest := ref.Context().Digest(h.String())

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	sv, err := signature.LoadECDSASignerVerifier(key, crypto.SHA256)
	require.NoError(t, err)
	pem, err := cryptoutils.MarshalPublicKeyToPEM(&key.PublicKey)
	require.NoError(t, err)
	keyPath := filepath.Join(t.TempDir(), "cosign.pub")
	require.NoError(t, os.WriteFile(keyPath, pem, 0600))

	const predicateType = "https://example.com/attestation"
	statement, err := json.Marshal(in_toto.Statement{
		StatementHeader: in_toto.StatementHeader{
			Type:          in_toto.StatementInTotoV01,
			PredicateType: predicateType,
			Subject: []in_toto.Subject{{
				Name:   ref.Context().Name(),
				Digest: map[string]string{h.Algorithm: h.Hex},
			}},
		},
		Predicate: map[string]interface{}{"test": true},
	})
	require.NoError(t, err)
	envelope, err := sigdsse.WrapSigner(sv, types.IntotoPayloadType).SignMessage(bytes.NewReader(statement))
	require.NoError(t, err)
	att, err := static.NewAttestation(envelope)
	require.NoError(t, err)
	se, err := mutate.AttachAttestationToEntity(signed.Image(img), att)
	require.NoError(t, err)
	require.NoError(t, ociremote.WriteAttestationsReferrer(digest, se, ociremote.WithRemoteOptions(rOpts...)))

	for _, enabled := range []bool{false, true} {
		for _, bundleFormat := range []bool{false, true} {
			t.Run(fmt.Sprintf("experimental=%t/bundle=%t", enabled, bundleFormat), func(t *testing.T) {
				cmd := VerifyAttestationCommand{
					RegistryOptions: options.RegistryOptions{RegistryClientOpts: rOpts},
					CommonVerifyOptions: options.CommonVerifyOptions{
						ExperimentalOCI11: enabled,
						NewBundleFormat:   bundleFormat,
					},
					KeyRef:        keyPath,
					IgnoreTlog:    true,
					IgnoreSCT:     true,
					CheckClaims:   true,
					PredicateType: predicateType,
					Output:        "json",
				}
				err := cmd.Exec(context.Background(), []string{ref.String()})
				if enabled {
					require.NoError(t, err)
				} else {
					require.Error(t, err)
				}
			})
		}
	}
}

func TestVerifyAttestationMissingSubject(t *testing.T) {
	ctx := context.Background()

	verifyAttestation := VerifyAttestationCommand{
		CertRef: "cert.pem",
		CertVerifyOptions: options.CertVerifyOptions{
			CertOidcIssuer: "issuer",
		},
	}

	err := verifyAttestation.Exec(ctx, []string{"foo", "bar", "baz"})
	if err == nil {
		t.Fatal("verifyAttestation expected 'need --certificate-identity'")
	}
}

func TestVerifyAttestationMissingIssuer(t *testing.T) {
	ctx := context.Background()

	verifyAttestation := VerifyAttestationCommand{
		CertRef: "cert.pem",
		CertVerifyOptions: options.CertVerifyOptions{
			CertIdentity: "subject",
		},
	}

	err := verifyAttestation.Exec(ctx, []string{"foo", "bar", "baz"})
	if err == nil {
		t.Fatal("verifyAttestation expected 'need --certificate-oidc-issuer'")
	}
}

func TestVerifyAttestationMutuallyExclusiveFlags(t *testing.T) {
	ctx := context.Background()
	tts := []struct {
		name          string
		cmd           VerifyAttestationCommand
		expectedError error
	}{
		{
			name: "both key and cert identity",
			cmd: VerifyAttestationCommand{
				KeyRef: "key.pub",
				CertVerifyOptions: options.CertVerifyOptions{
					CertIdentity: "hello@foo.com",
				},
			},
			expectedError: &options.KeyAndIdentityParseError{},
		},
		{
			name: "both key and cert identity regexp",
			cmd: VerifyAttestationCommand{
				KeyRef: "key.pub",
				CertVerifyOptions: options.CertVerifyOptions{
					CertIdentityRegexp: "^.*@foo.com$",
				},
			},
			expectedError: &options.KeyAndIdentityParseError{},
		},
		{
			name: "both cert identity and cert identity regexp",
			cmd: VerifyAttestationCommand{
				CertVerifyOptions: options.CertVerifyOptions{
					CertIdentity:       "hello@foo.com",
					CertIdentityRegexp: "^.*@foo.com$",
				},
			},
			expectedError: &options.KeyAndIdentityParseError{},
		},
		{
			name: "both key and security key",
			cmd: VerifyAttestationCommand{
				KeyRef: "key.pub",
				Sk:     true,
			},
			expectedError: &options.KeyParseError{},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Exec(ctx, []string{"foo", "bar", "baz"})
			if !errors.Is(err, tt.expectedError) {
				t.Fatalf("expected %T, got: %T, %v", tt.expectedError, err, err)
			}
		})
	}
}

func TestVerifyAttestationSkWithoutIdentities(t *testing.T) {
	ctx := context.Background()
	verifyAttestation := VerifyAttestationCommand{
		Sk: true,
	}

	err := verifyAttestation.Exec(ctx, []string{"foo"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "opening piv token") {
		t.Fatalf("expected PIV error, got: %v", err)
	}
}
