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
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/attest"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/initialize"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/sign"
	cliverify "github.com/sigstore/cosign/v3/cmd/cosign/cli/verify"
	"github.com/sigstore/cosign/v3/pkg/cosign"
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

	ctx := context.Background()
	tufLocalCache := t.TempDir()
	t.Setenv("TUF_ROOT", tufLocalCache)
	rootPath := os.Getenv("TUF_ROOT_JSON")
	mirror := os.Getenv("TUF_MIRROR")
	must(initialize.DoInitialize(ctx, rootPath, mirror), t)

	ko := options.KeyOpts{
		KeyRef:           privKey,
		PassFunc:         passFunc,
		RekorURL:         rekorURL,
		RekorVersion:     1,
		SkipConfirmation: true,
	}
	trustedMaterial, err := cosign.TrustedRoot()
	must(err, t)
	ko.TrustedMaterial = trustedMaterial

	// Sign without bundle format
	so := options.SignOptions{
		Upload:     true,
		TlogUpload: true,
	}
	mustErr(sign.SignCmd(t.Context(), ro, ko, so, []string{imgName}), t)
	so.Registry = options.RegistryOptions{
		AllowInsecure:     true,
		AllowHTTPRegistry: true,
	}
	if useOCI11 {
		so.RegistryExperimental = options.RegistryExperimentalOptions{
			RegistryReferrersMode: options.RegistryReferrersModeOCI11,
		}
	}
	must(sign.SignCmd(t.Context(), ro, ko, so, []string{imgName}), t)
	mustErr(verify(pubKey, imgName, true, nil, "", false), t)
	cmd := cliverify.VerifyCommand{
		KeyRef:      pubKey,
		CheckClaims: true,
		RegistryOptions: options.RegistryOptions{
			AllowInsecure:     true,
			AllowHTTPRegistry: true,
		},
	}
	if useOCI11 {
		cmd.ExperimentalOCI11 = true
	}
	must(cmd.Exec(context.Background(), []string{imgName}), t)

	// Sign new image with new bundle format
	// (Must be a new image or the old bundle may be verified instead)
	imgName = path.Join(repo, "cosign-registry-e2e-2")
	cleanup2 := makeImageIndexWithInsecureRegistry(t, imgName)
	defer cleanup2()

	so.NewBundleFormat = true
	must(sign.SignCmd(t.Context(), ro, ko, so, []string{imgName}), t)
	cmd.NewBundleFormat = true
	must(cmd.Exec(context.Background(), []string{imgName}), t)
}

func TestAttestInsecureRegistry(t *testing.T) {
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

	rekorURL := os.Getenv(rekorURLVar)

	ctx := context.Background()
	tufLocalCache := t.TempDir()
	t.Setenv("TUF_ROOT", tufLocalCache)
	rootPath := os.Getenv("TUF_ROOT_JSON")
	mirror := os.Getenv("TUF_MIRROR")
	must(initialize.DoInitialize(ctx, rootPath, mirror), t)

	ko := options.KeyOpts{
		KeyRef:           privKey,
		PassFunc:         passFunc,
		RekorURL:         rekorURL,
		RekorVersion:     1,
		SkipConfirmation: true,
	}
	trustedMaterial, err := cosign.TrustedRoot()
	must(err, t)
	ko.TrustedMaterial = trustedMaterial

	slsaAttestation := `{ "buildType": "x", "builder": { "id": "2" }, "recipe": {} }`
	slsaAttestationPath := filepath.Join(td, "attestation.slsa.json")
	if err := os.WriteFile(slsaAttestationPath, []byte(slsaAttestation), 0o600); err != nil {
		t.Fatal(err)
	}

	// Attest without bundle
	attestCmd := attest.AttestCommand{
		KeyOpts:        ko,
		PredicatePath:  slsaAttestationPath,
		PredicateType:  "slsaprovenance",
		Timeout:        30 * time.Second,
		RekorEntryType: "dsse",
		TlogUpload:     true,
		RegistryOptions: options.RegistryOptions{
			AllowInsecure:     true,
			AllowHTTPRegistry: true,
		},
	}
	must(attestCmd.Exec(ctx, imgName), t)
	verifyAttestation := cliverify.VerifyAttestationCommand{
		KeyRef:        pubKey,
		PredicateType: "slsaprovenance",
		RegistryOptions: options.RegistryOptions{
			AllowInsecure:     true,
			AllowHTTPRegistry: true,
		},
	}
	must(verifyAttestation.Exec(ctx, []string{imgName}), t)

	// Attest with new bundle
	imgName = path.Join(repo, "cosign-registry-e2e-2")
	cleanup2 := makeImageIndexWithInsecureRegistry(t, imgName)
	defer cleanup2()

	ko.NewBundleFormat = true
	attestCmd.KeyOpts = ko
	must(attestCmd.Exec(ctx, imgName), t)
	verifyAttestation.CommonVerifyOptions.NewBundleFormat = true
	verifyAttestation.IgnoreTlog = false
	must(verifyAttestation.Exec(ctx, []string{imgName}), t)
}

func makeImageIndexWithInsecureRegistry(t *testing.T, n string) func() {
	ref, err := name.ParseReference(n, name.WeakValidation, name.Insecure)
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
