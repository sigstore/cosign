// Copyright 2024 The Sigstore Authors.
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

//go:build e2e && registry

package test

import (
	"context"
	"crypto/tls"
	"net/http"
	"os"
	"path"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/sign"
	cliverify "github.com/sigstore/cosign/v3/cmd/cosign/cli/verify"
	"github.com/sigstore/cosign/v3/pkg/cosign/env"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
)

const (
	oci11Var    = "OCI11"
	rekorURLVar = "REKOR_URL"
)

func TestInsecureRegistry(t *testing.T) {
	if os.Getenv("COSIGN_TEST_REPO") == "" {
		t.Fatal("COSIGN_TEST_REPO must be set to an insecure registry for this test")
	}
	repo, stop := reg(t)
	defer stop()
	td := t.TempDir()

	imgName := path.Join(repo, "cosign-registry-e2e")
	cleanup := makeImageIndexWithInsecureRegistry(t, imgName)
	defer cleanup()

	_, privKey, pubKey := keypair(t, td)

	useOCI11 := os.Getenv("oci11Var") != ""

	rekorURL := os.Getenv(rekorURLVar)
	must(downloadAndSetEnv(t, rekorURL+"/api/v1/log/publicKey", env.VariableSigstoreRekorPublicKey.String(), td), t)

	ko := options.KeyOpts{
		KeyRef:           privKey,
		PassFunc:         passFunc,
		RekorURL:         rekorURL,
		SkipConfirmation: true,
	}
	so := options.SignOptions{
		Upload:     true,
		TlogUpload: true,
	}
	mustErr(sign.SignCmd(ro, ko, so, []string{imgName}), t)
	so.Registry = options.RegistryOptions{
		AllowInsecure: true,
	}
	if useOCI11 {
		so.RegistryExperimental = options.RegistryExperimentalOptions{
			RegistryReferrersMode: options.RegistryReferrersModeOCI11,
		}
	}
	must(sign.SignCmd(ro, ko, so, []string{imgName}), t)
	mustErr(verify(pubKey, imgName, true, nil, "", false), t)
	cmd := cliverify.VerifyCommand{
		KeyRef:      pubKey,
		CheckClaims: true,
		RegistryOptions: options.RegistryOptions{
			AllowInsecure: true,
		},
	}
	if useOCI11 {
		cmd.ExperimentalOCI11 = true
	}
	must(cmd.Exec(context.Background(), []string{imgName}), t)
}

func makeImageIndexWithInsecureRegistry(t *testing.T, n string) func() {
	ref, err := name.ParseReference(n, name.WeakValidation)
	if err != nil {
		t.Fatal(err)
	}
	index, err := random.Index(512, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	regClientOpts := registryClientOpts(context.Background())
	// Add TLS config to allow us to push the image to the insecure registry
	insecureTransport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	regClientOpts = append(regClientOpts, remote.WithTransport(insecureTransport))
	if err := remote.WriteIndex(ref, index, regClientOpts...); err != nil {
		t.Fatal(err)
	}
	remoteImage, err := remote.Get(ref, regClientOpts...)
	if err != nil {
		t.Fatal(err)
	}
	cleanup := func() {
		_ = remote.Delete(ref, regClientOpts...)
		ref, _ := ociremote.SignatureTag(ref.Context().Digest(remoteImage.Descriptor.Digest.String()), ociremote.WithRemoteOptions(regClientOpts...))
		_ = remote.Delete(ref, regClientOpts...)
	}
	return cleanup
}
