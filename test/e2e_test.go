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

//go:build e2e
// +build e2e

package test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-openapi/strfmt"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8s "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	// Initialize all known client auth plugins
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"github.com/sigstore/cosign/v2/cmd/cosign/cli"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/attach"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/attest"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/download"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/publickey"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/sign"
	cliverify "github.com/sigstore/cosign/v2/cmd/cosign/cli/verify"
	"github.com/sigstore/cosign/v2/internal/pkg/cosign/tsa"
	"github.com/sigstore/cosign/v2/internal/pkg/cosign/tsa/client"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v2/pkg/cosign/env"
	"github.com/sigstore/cosign/v2/pkg/cosign/kubernetes"
	"github.com/sigstore/cosign/v2/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	sigs "github.com/sigstore/cosign/v2/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/payload"
	tsaclient "github.com/sigstore/timestamp-authority/pkg/client"
	"github.com/sigstore/timestamp-authority/pkg/server"
	"github.com/spf13/viper"
)

const (
	serverEnv = "REKOR_SERVER"
	rekorURL  = "https://rekor.sigstore.dev"
	fulcioURL = "https://fulcio.sigstore.dev"
)

var keyPass = []byte("hello")

var passFunc = func(_ bool) ([]byte, error) {
	return keyPass, nil
}

var verify = func(keyRef, imageRef string, checkClaims bool, annotations map[string]interface{}, attachment string) error {
	cmd := cliverify.VerifyCommand{
		KeyRef:        keyRef,
		RekorURL:      rekorURL,
		CheckClaims:   checkClaims,
		Annotations:   sigs.AnnotationsMap{Annotations: annotations},
		Attachment:    attachment,
		HashAlgorithm: crypto.SHA256,
		IgnoreTlog:    true,
		MaxWorkers:    10,
	}

	args := []string{imageRef}

	return cmd.Exec(context.Background(), args)
}

var verifyTSA = func(keyRef, imageRef string, checkClaims bool, annotations map[string]interface{}, attachment, tsaCertChain string, skipTlogVerify bool) error {
	cmd := cliverify.VerifyCommand{
		KeyRef:           keyRef,
		CheckClaims:      checkClaims,
		Annotations:      sigs.AnnotationsMap{Annotations: annotations},
		Attachment:       attachment,
		HashAlgorithm:    crypto.SHA256,
		TSACertChainPath: tsaCertChain,
		IgnoreTlog:       skipTlogVerify,
		MaxWorkers:       10,
	}

	args := []string{imageRef}

	return cmd.Exec(context.Background(), args)
}

var verifyKeylessTSA = func(imageRef string, tsaCertChain string, skipSCT bool, skipTlogVerify bool) error {
	cmd := cliverify.VerifyCommand{
		CertVerifyOptions: options.CertVerifyOptions{
			CertOidcIssuerRegexp: ".*",
			CertIdentityRegexp:   ".*",
		},
		HashAlgorithm:    crypto.SHA256,
		TSACertChainPath: tsaCertChain,
		IgnoreSCT:        skipSCT,
		IgnoreTlog:       skipTlogVerify,
		MaxWorkers:       10,
	}

	args := []string{imageRef}

	return cmd.Exec(context.Background(), args)
}

// Used to verify local images stored on disk
var verifyLocal = func(keyRef, path string, checkClaims bool, annotations map[string]interface{}, attachment string) error {
	cmd := cliverify.VerifyCommand{
		KeyRef:        keyRef,
		CheckClaims:   checkClaims,
		Annotations:   sigs.AnnotationsMap{Annotations: annotations},
		Attachment:    attachment,
		HashAlgorithm: crypto.SHA256,
		LocalImage:    true,
		IgnoreTlog:    true,
		MaxWorkers:    10,
	}

	args := []string{path}

	return cmd.Exec(context.Background(), args)
}

var ro = &options.RootOptions{Timeout: options.DefaultTimeout}

func TestSignVerify(t *testing.T) {
	repo, stop := reg(t)
	defer stop()
	td := t.TempDir()

	imgName := path.Join(repo, "cosign-e2e")

	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	_, privKeyPath, pubKeyPath := keypair(t, td)

	ctx := context.Background()
	// Verify should fail at first
	mustErr(verify(pubKeyPath, imgName, true, nil, ""), t)
	// So should download
	mustErr(download.SignatureCmd(ctx, options.RegistryOptions{}, imgName), t)

	// Now sign the image
	ko := options.KeyOpts{KeyRef: privKeyPath, PassFunc: passFunc}
	so := options.SignOptions{
		Upload: true,
	}
	must(sign.SignCmd(ro, ko, so, []string{imgName}), t)

	// Now verify and download should work!
	must(verify(pubKeyPath, imgName, true, nil, ""), t)
	must(download.SignatureCmd(ctx, options.RegistryOptions{}, imgName), t)

	// Look for a specific annotation
	mustErr(verify(pubKeyPath, imgName, true, map[string]interface{}{"foo": "bar"}, ""), t)

	so.AnnotationOptions = options.AnnotationOptions{
		Annotations: []string{"foo=bar"},
	}
	// Sign the image with an annotation
	must(sign.SignCmd(ro, ko, so, []string{imgName}), t)

	// It should match this time.
	must(verify(pubKeyPath, imgName, true, map[string]interface{}{"foo": "bar"}, ""), t)

	// But two doesn't work
	mustErr(verify(pubKeyPath, imgName, true, map[string]interface{}{"foo": "bar", "baz": "bat"}, ""), t)
}

func TestSignVerifyClean(t *testing.T) {
	repo, stop := reg(t)
	defer stop()
	td := t.TempDir()

	imgName := path.Join(repo, "cosign-e2e")

	_, _, _ = mkimage(t, imgName)

	_, privKeyPath, pubKeyPath := keypair(t, td)

	ctx := context.Background()

	// Now sign the image
	ko := options.KeyOpts{KeyRef: privKeyPath, PassFunc: passFunc}
	so := options.SignOptions{
		Upload: true,
	}
	must(sign.SignCmd(ro, ko, so, []string{imgName}), t)

	// Now verify and download should work!
	must(verify(pubKeyPath, imgName, true, nil, ""), t)
	must(download.SignatureCmd(ctx, options.RegistryOptions{}, imgName), t)

	// Now clean signature from the given image
	must(cli.CleanCmd(ctx, options.RegistryOptions{}, "all", imgName, true), t)

	// It doesn't work
	mustErr(verify(pubKeyPath, imgName, true, nil, ""), t)
}

func TestImportSignVerifyClean(t *testing.T) {

	repo, stop := reg(t)
	defer stop()
	td := t.TempDir()

	imgName := path.Join(repo, "cosign-e2e")

	_, _, _ = mkimage(t, imgName)

	_, privKeyPath, pubKeyPath := importKeyPair(t, td)

	ctx := context.Background()

	// Now sign the image
	ko := options.KeyOpts{KeyRef: privKeyPath, PassFunc: passFunc}
	so := options.SignOptions{
		Upload: true,
	}
	must(sign.SignCmd(ro, ko, so, []string{imgName}), t)

	// Now verify and download should work!
	must(verify(pubKeyPath, imgName, true, nil, ""), t)
	must(download.SignatureCmd(ctx, options.RegistryOptions{}, imgName), t)

	// Now clean signature from the given image
	must(cli.CleanCmd(ctx, options.RegistryOptions{}, "all", imgName, true), t)

	// It doesn't work
	mustErr(verify(pubKeyPath, imgName, true, nil, ""), t)
}

func TestAttestVerify(t *testing.T) {
	attestVerify(t,
		"slsaprovenance",
		`{ "buildType": "x", "builder": { "id": "2" }, "recipe": {} }`,
		`predicate: builder: id: "2"`,
		`predicate: builder: id: "1"`,
	)
}

func TestAttestVerifySPDXJSON(t *testing.T) {
	attestationBytes, err := os.ReadFile("./testdata/bom-go-mod.spdx.json")
	if err != nil {
		t.Fatal(err)
	}
	attestVerify(t,
		"spdxjson",
		string(attestationBytes),
		`predicate: spdxVersion: "SPDX-2.2"`,
		`predicate: spdxVersion: "SPDX-9.9"`,
	)
}

func TestAttestVerifyCycloneDXJSON(t *testing.T) {
	attestationBytes, err := os.ReadFile("./testdata/bom-go-mod.cyclonedx.json")
	if err != nil {
		t.Fatal(err)
	}
	attestVerify(t,
		"cyclonedx",
		string(attestationBytes),
		`predicate: specVersion: "1.4"`,
		`predicate: specVersion: "7.7"`,
	)
}

func TestAttestVerifyURI(t *testing.T) {
	attestationBytes, err := os.ReadFile("./testdata/test-result.json")
	if err != nil {
		t.Fatal(err)
	}
	attestVerify(t,
		"https://example.com/TestResult/v1",
		string(attestationBytes),
		`predicate: passed: true`,
		`predicate: passed: false"`,
	)
}

func attestVerify(t *testing.T, predicateType, attestation, goodCue, badCue string) {
	repo, stop := reg(t)
	defer stop()
	td := t.TempDir()

	var imgName, attestationPath string
	if _, err := url.ParseRequestURI(predicateType); err == nil {
		// If the predicate type is URI, it cannot be included as image name and path.
		imgName = path.Join(repo, "cosign-attest-uri-e2e-image")
		attestationPath = filepath.Join(td, "cosign-attest-uri-e2e-attestation")
	} else {
		imgName = path.Join(repo, fmt.Sprintf("cosign-attest-%s-e2e-image", predicateType))
		attestationPath = filepath.Join(td, fmt.Sprintf("cosign-attest-%s-e2e-attestation", predicateType))
	}

	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	_, privKeyPath, pubKeyPath := keypair(t, td)

	ctx := context.Background()

	// Verify should fail at first
	verifyAttestation := cliverify.VerifyAttestationCommand{
		KeyRef:     pubKeyPath,
		IgnoreTlog: true,
		MaxWorkers: 10,
	}

	// Fail case when using without type and policy flag
	mustErr(verifyAttestation.Exec(ctx, []string{imgName}), t)

	if err := os.WriteFile(attestationPath, []byte(attestation), 0600); err != nil {
		t.Fatal(err)
	}

	// Now attest the image
	ko := options.KeyOpts{KeyRef: privKeyPath, PassFunc: passFunc}
	attestCmd := attest.AttestCommand{
		KeyOpts:       ko,
		PredicatePath: attestationPath,
		PredicateType: predicateType,
		Timeout:       30 * time.Second,
	}
	must(attestCmd.Exec(ctx, imgName), t)

	// Use cue to verify attestation
	policyPath := filepath.Join(td, "policy.cue")
	verifyAttestation.PredicateType = predicateType
	verifyAttestation.Policies = []string{policyPath}

	// Fail case
	if err := os.WriteFile(policyPath, []byte(badCue), 0600); err != nil {
		t.Fatal(err)
	}
	mustErr(verifyAttestation.Exec(ctx, []string{imgName}), t)

	// Success case
	if err := os.WriteFile(policyPath, []byte(goodCue), 0600); err != nil {
		t.Fatal(err)
	}
	must(verifyAttestation.Exec(ctx, []string{imgName}), t)

	// Look for a specific annotation
	mustErr(verify(pubKeyPath, imgName, true, map[string]interface{}{"foo": "bar"}, ""), t)
}

func TestAttestationDownload(t *testing.T) {
	repo, stop := reg(t)
	defer stop()
	td := t.TempDir()

	imgName := path.Join(repo, "cosign-attest-download-e2e")

	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	_, privKeyPath, _ := keypair(t, td)
	ko := options.KeyOpts{KeyRef: privKeyPath, PassFunc: passFunc}

	ctx := context.Background()

	slsaAttestation := `{ "buildType": "x", "builder": { "id": "2" }, "recipe": {} }`
	slsaAttestationPath := filepath.Join(td, "attestation.slsa.json")
	if err := os.WriteFile(slsaAttestationPath, []byte(slsaAttestation), 0600); err != nil {
		t.Fatal(err)
	}

	vulnAttestation := `
	{
    "invocation": {
      "parameters": null,
      "uri": "invocation.example.com/cosign-testing",
      "event_id": "",
      "builder.id": ""
    },
    "scanner": {
      "uri": "fakescanner.example.com/cosign-testing",
      "version": "",
      "db": {
        "uri": "",
        "version": ""
      },
      "result": null
    },
    "metadata": {
      "scanStartedOn": "2022-04-12T00:00:00Z",
      "scanFinishedOn": "2022-04-12T00:10:00Z"
    }
}
`
	vulnAttestationPath := filepath.Join(td, "attestation.vuln.json")
	if err := os.WriteFile(vulnAttestationPath, []byte(vulnAttestation), 0600); err != nil {
		t.Fatal(err)
	}

	ref, err := name.ParseReference(imgName)
	if err != nil {
		t.Fatal(err)
	}
	regOpts := options.RegistryOptions{}
	ociremoteOpts, err := regOpts.ClientOpts(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Attest to create a slsa attestation
	attestCommand := attest.AttestCommand{
		KeyOpts:       ko,
		PredicatePath: slsaAttestationPath,
		PredicateType: "slsaprovenance",
		Timeout:       30 * time.Second,
		Replace:       true,
	}
	must(attestCommand.Exec(ctx, imgName), t)

	// Attest to create a vuln attestation
	attestCommand = attest.AttestCommand{
		KeyOpts:       ko,
		PredicatePath: vulnAttestationPath,
		PredicateType: "vuln",
		Timeout:       30 * time.Second,
		Replace:       true,
	}
	must(attestCommand.Exec(ctx, imgName), t)

	// Call download.AttestationCmd() to ensure success
	attOpts := options.AttestationDownloadOptions{}
	must(download.AttestationCmd(ctx, regOpts, attOpts, imgName), t)

	attestations, err := cosign.FetchAttestationsForReference(ctx, ref, attOpts.PredicateType, ociremoteOpts...)
	if err != nil {
		t.Fatal(err)
	}
	if len(attestations) != 2 {
		t.Fatal(fmt.Errorf("expected len(attestations) == 2, got %d", len(attestations)))
	}
}

func TestAttestationDownloadWithPredicateType(t *testing.T) {
	repo, stop := reg(t)
	defer stop()
	td := t.TempDir()

	imgName := path.Join(repo, "cosign-attest-download-predicate-type-e2e")

	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	_, privKeyPath, _ := keypair(t, td)
	ko := options.KeyOpts{KeyRef: privKeyPath, PassFunc: passFunc}

	ctx := context.Background()

	slsaAttestation := `{ "buildType": "x", "builder": { "id": "2" }, "recipe": {} }`
	slsaAttestationPath := filepath.Join(td, "attestation.slsa.json")
	if err := os.WriteFile(slsaAttestationPath, []byte(slsaAttestation), 0600); err != nil {
		t.Fatal(err)
	}

	vulnAttestation := `
	{
    "invocation": {
      "parameters": null,
      "uri": "invocation.example.com/cosign-testing",
      "event_id": "",
      "builder.id": ""
    },
    "scanner": {
      "uri": "fakescanner.example.com/cosign-testing",
      "version": "",
      "db": {
        "uri": "",
        "version": ""
      },
      "result": null
    },
    "metadata": {
      "scanStartedOn": "2022-04-12T00:00:00Z",
      "scanFinishedOn": "2022-04-12T00:10:00Z"
    }
}
`
	vulnAttestationPath := filepath.Join(td, "attestation.vuln.json")
	if err := os.WriteFile(vulnAttestationPath, []byte(vulnAttestation), 0600); err != nil {
		t.Fatal(err)
	}

	ref, err := name.ParseReference(imgName)
	if err != nil {
		t.Fatal(err)
	}
	regOpts := options.RegistryOptions{}
	ociremoteOpts, err := regOpts.ClientOpts(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Attest to create a slsa attestation
	attestCommand := attest.AttestCommand{
		KeyOpts:       ko,
		PredicatePath: slsaAttestationPath,
		PredicateType: "slsaprovenance",
		Timeout:       30 * time.Second,
		Replace:       true,
	}
	must(attestCommand.Exec(ctx, imgName), t)

	// Attest to create a vuln attestation
	attestCommand = attest.AttestCommand{
		KeyOpts:       ko,
		PredicatePath: vulnAttestationPath,
		PredicateType: "vuln",
		Timeout:       30 * time.Second,
		Replace:       true,
	}
	must(attestCommand.Exec(ctx, imgName), t)

	// Call download.AttestationCmd() to ensure success with --predicate-type
	attOpts := options.AttestationDownloadOptions{
		PredicateType: "vuln",
	}
	must(download.AttestationCmd(ctx, regOpts, attOpts, imgName), t)

	predicateType, _ := options.ParsePredicateType(attOpts.PredicateType)
	attestations, err := cosign.FetchAttestationsForReference(ctx, ref, predicateType, ociremoteOpts...)
	if err != nil {
		t.Fatal(err)
	}
	if len(attestations) != 1 {
		t.Fatal(fmt.Errorf("expected len(attestations) == 1, got %d", len(attestations)))
	}
}

func TestAttestationDownloadWithBadPredicateType(t *testing.T) {
	repo, stop := reg(t)
	defer stop()
	td := t.TempDir()

	imgName := path.Join(repo, "cosign-attest-download-bad-type-e2e")

	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	_, privKeyPath, _ := keypair(t, td)
	ko := options.KeyOpts{KeyRef: privKeyPath, PassFunc: passFunc}

	ctx := context.Background()

	slsaAttestation := `{ "buildType": "x", "builder": { "id": "2" }, "recipe": {} }`
	slsaAttestationPath := filepath.Join(td, "attestation.slsa.json")
	if err := os.WriteFile(slsaAttestationPath, []byte(slsaAttestation), 0600); err != nil {
		t.Fatal(err)
	}

	regOpts := options.RegistryOptions{}

	// Attest to create a slsa attestation
	attestCommand := attest.AttestCommand{
		KeyOpts:       ko,
		PredicatePath: slsaAttestationPath,
		PredicateType: "slsaprovenance",
		Timeout:       30 * time.Second,
		Replace:       true,
	}
	must(attestCommand.Exec(ctx, imgName), t)

	// Call download.AttestationCmd() to ensure failure with non-existant --predicate-type
	attOpts := options.AttestationDownloadOptions{
		PredicateType: "vuln",
	}
	mustErr(download.AttestationCmd(ctx, regOpts, attOpts, imgName), t)
}

func TestAttestationReplaceCreate(t *testing.T) {
	repo, stop := reg(t)
	defer stop()
	td := t.TempDir()

	imgName := path.Join(repo, "cosign-attest-replace-e2e")

	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	_, privKeyPath, _ := keypair(t, td)
	ko := options.KeyOpts{KeyRef: privKeyPath, PassFunc: passFunc}

	ctx := context.Background()

	slsaAttestation := `{ "buildType": "x", "builder": { "id": "2" }, "recipe": {} }`
	slsaAttestationPath := filepath.Join(td, "attestation.slsa.json")
	if err := os.WriteFile(slsaAttestationPath, []byte(slsaAttestation), 0600); err != nil {
		t.Fatal(err)
	}

	ref, err := name.ParseReference(imgName)
	if err != nil {
		t.Fatal(err)
	}
	regOpts := options.RegistryOptions{}
	ociremoteOpts, err := regOpts.ClientOpts(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Attest with replace=true to create an attestation
	attestCommand := attest.AttestCommand{
		KeyOpts:       ko,
		PredicatePath: slsaAttestationPath,
		PredicateType: "slsaprovenance",
		Timeout:       30 * time.Second,
		Replace:       true,
	}
	must(attestCommand.Exec(ctx, imgName), t)

	// Download and count the attestations
	attOpts := options.AttestationDownloadOptions{}
	attestations, err := cosign.FetchAttestationsForReference(ctx, ref, attOpts.PredicateType, ociremoteOpts...)
	if err != nil {
		t.Fatal(err)
	}
	if len(attestations) != 1 {
		t.Fatal(fmt.Errorf("expected len(attestations) == 1, got %d", len(attestations)))
	}
}

func TestAttestationReplace(t *testing.T) {
	repo, stop := reg(t)
	defer stop()
	td := t.TempDir()

	imgName := path.Join(repo, "cosign-attest-replace-e2e")

	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	_, privKeyPath, _ := keypair(t, td)
	ko := options.KeyOpts{KeyRef: privKeyPath, PassFunc: passFunc}

	ctx := context.Background()

	slsaAttestation := `{ "buildType": "x", "builder": { "id": "2" }, "recipe": {} }`
	slsaAttestationPath := filepath.Join(td, "attestation.slsa.json")
	if err := os.WriteFile(slsaAttestationPath, []byte(slsaAttestation), 0600); err != nil {
		t.Fatal(err)
	}

	ref, err := name.ParseReference(imgName)
	if err != nil {
		t.Fatal(err)
	}
	regOpts := options.RegistryOptions{}
	ociremoteOpts, err := regOpts.ClientOpts(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Attest once with replace=false creating an attestation
	attestCommand := attest.AttestCommand{
		KeyOpts:       ko,
		PredicatePath: slsaAttestationPath,
		PredicateType: "slsaprovenance",
		Timeout:       30 * time.Second,
	}
	must(attestCommand.Exec(ctx, imgName), t)

	// Download and count the attestations
	attOpts := options.AttestationDownloadOptions{}
	attestations, err := cosign.FetchAttestationsForReference(ctx, ref, attOpts.PredicateType, ociremoteOpts...)
	if err != nil {
		t.Fatal(err)
	}
	if len(attestations) != 1 {
		t.Fatal(fmt.Errorf("expected len(attestations) == 1, got %d", len(attestations)))
	}

	// Attest again with replace=true, replacing the previous attestation
	attestCommand = attest.AttestCommand{
		KeyOpts:       ko,
		PredicatePath: slsaAttestationPath,
		PredicateType: "slsaprovenance",
		Replace:       true,
		Timeout:       30 * time.Second,
	}
	must(attestCommand.Exec(ctx, imgName), t)
	attestations, err = cosign.FetchAttestationsForReference(ctx, ref, attOpts.PredicateType, ociremoteOpts...)

	// Download and count the attestations
	if err != nil {
		t.Fatal(err)
	}
	if len(attestations) != 1 {
		t.Fatal(fmt.Errorf("expected len(attestations) == 1, got %d", len(attestations)))
	}

	// Attest once more replace=true using a different predicate, to ensure it adds a new attestation
	attestCommand = attest.AttestCommand{
		KeyOpts:       ko,
		PredicatePath: slsaAttestationPath,
		PredicateType: "custom",
		Replace:       true,
		Timeout:       30 * time.Second,
	}
	must(attestCommand.Exec(ctx, imgName), t)

	// Download and count the attestations
	attestations, err = cosign.FetchAttestationsForReference(ctx, ref, attOpts.PredicateType, ociremoteOpts...)
	if err != nil {
		t.Fatal(err)
	}
	if len(attestations) != 2 {
		t.Fatal(fmt.Errorf("expected len(attestations) == 2, got %d", len(attestations)))
	}
}

func TestAttestationRFC3161Timestamp(t *testing.T) {
	// TSA server needed to create timestamp
	viper.Set("timestamp-signer", "memory")
	viper.Set("timestamp-signer-hash", "sha256")
	apiServer := server.NewRestAPIServer("localhost", 0, []string{"http"}, false, 10*time.Second, 10*time.Second)
	server := httptest.NewServer(apiServer.GetHandler())
	t.Cleanup(server.Close)

	repo, stop := reg(t)
	defer stop()
	td := t.TempDir()

	imgName := path.Join(repo, "cosign-attest-timestamp-e2e")

	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	_, privKeyPath, pubKeyPath := keypair(t, td)
	ko := options.KeyOpts{KeyRef: privKeyPath, PassFunc: passFunc}

	ctx := context.Background()

	slsaAttestation := `{ "buildType": "x", "builder": { "id": "2" }, "recipe": {} }`
	slsaAttestationPath := filepath.Join(td, "attestation.slsa.json")
	if err := os.WriteFile(slsaAttestationPath, []byte(slsaAttestation), 0600); err != nil {
		t.Fatal(err)
	}

	ref, err := name.ParseReference(imgName)
	if err != nil {
		t.Fatal(err)
	}
	regOpts := options.RegistryOptions{}
	ociremoteOpts, err := regOpts.ClientOpts(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Attest with TSA and skipping tlog creating an attestation
	attestCommand := attest.AttestCommand{
		KeyOpts:       ko,
		PredicatePath: slsaAttestationPath,
		PredicateType: "slsaprovenance",
		Timeout:       30 * time.Second,
		TSAServerURL:  server.URL + "/api/v1/timestamp",
		TlogUpload:    false,
	}
	must(attestCommand.Exec(ctx, imgName), t)

	// Download and count the attestations
	attOpts := options.AttestationDownloadOptions{}
	attestations, err := cosign.FetchAttestationsForReference(ctx, ref, attOpts.PredicateType, ociremoteOpts...)
	if err != nil {
		t.Fatal(err)
	}
	if len(attestations) != 1 {
		t.Fatal(fmt.Errorf("expected len(attestations) == 1, got %d", len(attestations)))
	}

	client, err := tsaclient.GetTimestampClient(server.URL)
	if err != nil {
		t.Error(err)
	}

	chain, err := client.Timestamp.GetTimestampCertChain(nil)
	if err != nil {
		t.Fatalf("unexpected error getting timestamp chain: %v", err)
	}

	file, err := os.CreateTemp(os.TempDir(), "tempfile")
	if err != nil {
		t.Fatalf("error creating temp file: %v", err)
	}
	defer os.Remove(file.Name())
	_, err = file.WriteString(chain.Payload)
	if err != nil {
		t.Fatalf("error writing chain payload to temp file: %v", err)
	}

	verifyAttestation := cliverify.VerifyAttestationCommand{
		KeyRef:           pubKeyPath,
		TSACertChainPath: file.Name(),
		IgnoreTlog:       true,
		PredicateType:    "slsaprovenance",
		MaxWorkers:       10,
	}

	must(verifyAttestation.Exec(ctx, []string{imgName}), t)
}

func TestAttachWithRFC3161Timestamp(t *testing.T) {
	ctx := context.Background()
	// TSA server needed to create timestamp
	viper.Set("timestamp-signer", "memory")
	viper.Set("timestamp-signer-hash", "sha256")
	apiServer := server.NewRestAPIServer("localhost", 0, []string{"http"}, false, 10*time.Second, 10*time.Second)
	server := httptest.NewServer(apiServer.GetHandler())
	t.Cleanup(server.Close)

	repo, stop := reg(t)
	defer stop()
	td := t.TempDir()

	imgName := path.Join(repo, "cosign-attach-timestamp-e2e")

	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	b := bytes.Buffer{}
	must(generate.GenerateCmd(context.Background(), options.RegistryOptions{}, imgName, nil, &b), t)

	rootCert, rootKey, _ := GenerateRootCa()
	subCert, subKey, _ := GenerateSubordinateCa(rootCert, rootKey)
	leafCert, privKey, _ := GenerateLeafCert("subject@mail.com", "oidc-issuer", subCert, subKey)
	pemRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCert.Raw})
	pemSub := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: subCert.Raw})
	pemLeaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCert.Raw})

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	payloadref := mkfile(b.String(), td, t)

	h := sha256.Sum256(b.Bytes())
	signature, _ := privKey.Sign(rand.Reader, h[:], crypto.SHA256)
	b64signature := base64.StdEncoding.EncodeToString([]byte(signature))
	sigRef := mkfile(b64signature, td, t)
	pemleafRef := mkfile(string(pemLeaf), td, t)
	pemrootRef := mkfile(string(pemRoot), td, t)

	certchainRef := mkfile(string(append(pemSub[:], pemRoot[:]...)), td, t)

	t.Setenv("SIGSTORE_ROOT_FILE", pemrootRef)

	tsclient, err := tsaclient.GetTimestampClient(server.URL)
	if err != nil {
		t.Error(err)
	}

	chain, err := tsclient.Timestamp.GetTimestampCertChain(nil)
	if err != nil {
		t.Fatalf("unexpected error getting timestamp chain: %v", err)
	}

	file, err := os.CreateTemp(os.TempDir(), "tempfile")
	if err != nil {
		t.Fatalf("error creating temp file: %v", err)
	}
	defer os.Remove(file.Name())
	_, err = file.WriteString(chain.Payload)
	if err != nil {
		t.Fatalf("error writing chain payload to temp file: %v", err)
	}

	tsBytes, err := tsa.GetTimestampedSignature(signature, client.NewTSAClient(server.URL+"/api/v1/timestamp"))
	if err != nil {
		t.Fatalf("unexpected error creating timestamp: %v", err)
	}
	rfc3161TSRef := mkfile(string(tsBytes), td, t)

	// Upload it!
	err = attach.SignatureCmd(ctx, options.RegistryOptions{}, sigRef, payloadref, pemleafRef, certchainRef, rfc3161TSRef, "", imgName)
	if err != nil {
		t.Fatal(err)
	}

	must(verifyKeylessTSA(imgName, file.Name(), true, true), t)
}

func TestAttachWithRekorBundle(t *testing.T) {
	ctx := context.Background()

	repo, stop := reg(t)
	defer stop()
	td := t.TempDir()

	imgName := path.Join(repo, "cosign-attach-timestamp-e2e")

	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	b := bytes.Buffer{}
	must(generate.GenerateCmd(context.Background(), options.RegistryOptions{}, imgName, nil, &b), t)

	rootCert, rootKey, _ := GenerateRootCa()
	subCert, subKey, _ := GenerateSubordinateCa(rootCert, rootKey)
	leafCert, privKey, _ := GenerateLeafCert("subject@mail.com", "oidc-issuer", subCert, subKey)
	pemRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCert.Raw})
	pemSub := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: subCert.Raw})
	pemLeaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCert.Raw})

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	payloadref := mkfile(b.String(), td, t)

	h := sha256.Sum256(b.Bytes())
	signature, _ := privKey.Sign(rand.Reader, h[:], crypto.SHA256)
	b64signature := base64.StdEncoding.EncodeToString([]byte(signature))
	sigRef := mkfile(b64signature, td, t)
	pemleafRef := mkfile(string(pemLeaf), td, t)
	pemrootRef := mkfile(string(pemRoot), td, t)

	t.Setenv("SIGSTORE_ROOT_FILE", pemrootRef)

	certchainRef := mkfile(string(append(pemSub[:], pemRoot[:]...)), td, t)

	localPayload := cosign.LocalSignedPayload{
		Base64Signature: b64signature,
		Cert:            string(pemLeaf),
		Bundle: &bundle.RekorBundle{
			SignedEntryTimestamp: strfmt.Base64("MEUCIEDcarEwRYkrxE9ne+kzEVvUhnWaauYzxhUyXOLy1hwAAiEA4VdVCvNRs+D/5o33C2KBy+q2YX3lP4Y7nqRFU+K3hi0="),
			Payload: bundle.RekorPayload{
				Body:           "REMOVED",
				IntegratedTime: 1631646761,
				LogIndex:       693591,
				LogID:          "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
			},
		},
	}

	jsonBundle, err := json.Marshal(localPayload)
	if err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(td, "bundle.json")
	if err := os.WriteFile(bundlePath, jsonBundle, 0644); err != nil {
		t.Fatal(err)
	}

	// Upload it!
	err = attach.SignatureCmd(ctx, options.RegistryOptions{}, sigRef, payloadref, pemleafRef, certchainRef, "", bundlePath, imgName)
	if err != nil {
		t.Fatal(err)
	}
}

func TestRekorBundle(t *testing.T) {
	// turn on the tlog
	defer setenv(t, env.VariableExperimental.String(), "1")()

	repo, stop := reg(t)
	defer stop()
	td := t.TempDir()

	imgName := path.Join(repo, "cosign-e2e")

	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	_, privKeyPath, pubKeyPath := keypair(t, td)

	ko := options.KeyOpts{
		KeyRef:   privKeyPath,
		PassFunc: passFunc,
		RekorURL: rekorURL,
	}
	so := options.SignOptions{
		Upload: true,
	}

	// Sign the image
	must(sign.SignCmd(ro, ko, so, []string{imgName}), t)
	// Make sure verify works
	must(verify(pubKeyPath, imgName, true, nil, ""), t)

	// Make sure offline verification works with bundling
	// use rekor prod since we have hardcoded the public key
	os.Setenv(serverEnv, "notreal")
	must(verify(pubKeyPath, imgName, true, nil, ""), t)
}

func TestRekorOutput(t *testing.T) {
	repo, stop := reg(t)
	defer stop()
	td := t.TempDir()

	imgName := path.Join(repo, "cosign-e2e")
	bundlePath := filepath.Join(td, "bundle.sig")

	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	_, privKeyPath, pubKeyPath := keypair(t, td)

	ko := options.KeyOpts{
		KeyRef:     privKeyPath,
		PassFunc:   passFunc,
		RekorURL:   rekorURL,
		BundlePath: bundlePath,
	}
	so := options.SignOptions{
		Upload: true,
	}

	// Sign the image
	must(sign.SignCmd(ro, ko, so, []string{imgName}), t)
	// Make sure verify works
	must(verify(pubKeyPath, imgName, true, nil, ""), t)

	if file, err := os.ReadFile(bundlePath); err != nil {
		t.Fatal(err)
	} else {
		var localCosignPayload cosign.LocalSignedPayload
		if err := json.Unmarshal(file, &localCosignPayload); err != nil {
			t.Fatal(err)
		}
	}
	// Make sure offline verification works with bundling
	// use rekor prod since we have hardcoded the public key
	os.Setenv(serverEnv, "notreal")
	must(verify(pubKeyPath, imgName, true, nil, ""), t)
}

func TestFulcioBundle(t *testing.T) {
	repo, stop := reg(t)
	defer stop()
	td := t.TempDir()

	imgName := path.Join(repo, "cosign-e2e")

	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	_, privKeyPath, pubKeyPath := keypair(t, td)

	ko := options.KeyOpts{
		KeyRef:    privKeyPath,
		PassFunc:  passFunc,
		RekorURL:  rekorURL,
		FulcioURL: fulcioURL,
	}
	so := options.SignOptions{
		Upload:           true,
		IssueCertificate: true,
	}

	// Sign the image
	must(sign.SignCmd(ro, ko, so, []string{imgName}), t)
	// Make sure verify works
	must(verify(pubKeyPath, imgName, true, nil, ""), t)

	// Make sure offline verification works with bundling
	// use rekor prod since we have hardcoded the public key
	os.Setenv(serverEnv, "notreal")
	must(verify(pubKeyPath, imgName, true, nil, ""), t)
}

func TestRFC3161Timestamp(t *testing.T) {
	// TSA server needed to create timestamp
	viper.Set("timestamp-signer", "memory")
	viper.Set("timestamp-signer-hash", "sha256")
	apiServer := server.NewRestAPIServer("localhost", 0, []string{"http"}, false, 10*time.Second, 10*time.Second)
	server := httptest.NewServer(apiServer.GetHandler())
	t.Cleanup(server.Close)

	client, err := tsaclient.GetTimestampClient(server.URL)
	if err != nil {
		t.Error(err)
	}

	chain, err := client.Timestamp.GetTimestampCertChain(nil)
	if err != nil {
		t.Fatalf("unexpected error getting timestamp chain: %v", err)
	}

	file, err := os.CreateTemp(os.TempDir(), "tempfile")
	if err != nil {
		t.Fatalf("error creating temp file: %v", err)
	}
	defer os.Remove(file.Name())
	_, err = file.WriteString(chain.Payload)
	if err != nil {
		t.Fatalf("error writing chain payload to temp file: %v", err)
	}

	repo, stop := reg(t)
	defer stop()
	td := t.TempDir()

	imgName := path.Join(repo, "cosign-e2e")

	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	_, privKeyPath, pubKeyPath := keypair(t, td)

	ko := options.KeyOpts{
		KeyRef:       privKeyPath,
		PassFunc:     passFunc,
		TSAServerURL: server.URL + "/api/v1/timestamp",
	}
	so := options.SignOptions{
		Upload:     true,
		TlogUpload: false,
	}

	// Sign the image
	must(sign.SignCmd(ro, ko, so, []string{imgName}), t)
	// Make sure verify works against the TSA server
	must(verifyTSA(pubKeyPath, imgName, true, nil, "", file.Name(), true), t)
}

func TestRekorBundleAndRFC3161Timestamp(t *testing.T) {
	// TSA server needed to create timestamp
	viper.Set("timestamp-signer", "memory")
	viper.Set("timestamp-signer-hash", "sha256")
	apiServer := server.NewRestAPIServer("localhost", 0, []string{"http"}, false, 10*time.Second, 10*time.Second)
	server := httptest.NewServer(apiServer.GetHandler())
	t.Cleanup(server.Close)

	client, err := tsaclient.GetTimestampClient(server.URL)
	if err != nil {
		t.Error(err)
	}

	chain, err := client.Timestamp.GetTimestampCertChain(nil)
	if err != nil {
		t.Fatalf("unexpected error getting timestamp chain: %v", err)
	}

	file, err := os.CreateTemp(os.TempDir(), "tempfile")
	if err != nil {
		t.Fatalf("error creating temp file: %v", err)
	}
	defer os.Remove(file.Name())
	_, err = file.WriteString(chain.Payload)
	if err != nil {
		t.Fatalf("error writing chain payload to temp file: %v", err)
	}

	repo, stop := reg(t)
	defer stop()
	td := t.TempDir()

	imgName := path.Join(repo, "cosign-e2e")

	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	_, privKeyPath, pubKeyPath := keypair(t, td)

	ko := options.KeyOpts{
		KeyRef:           privKeyPath,
		PassFunc:         passFunc,
		TSAServerURL:     server.URL + "/api/v1/timestamp",
		RekorURL:         rekorURL,
		SkipConfirmation: true,
	}
	so := options.SignOptions{
		Upload:     true,
		TlogUpload: true,
	}

	// Sign the image
	must(sign.SignCmd(ro, ko, so, []string{imgName}), t)
	// Make sure verify works against the Rekor and TSA clients
	must(verifyTSA(pubKeyPath, imgName, true, nil, "", file.Name(), false), t)
}

func TestDuplicateSign(t *testing.T) {
	repo, stop := reg(t)
	defer stop()
	td := t.TempDir()

	imgName := path.Join(repo, "cosign-e2e")

	ref, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	_, privKeyPath, pubKeyPath := keypair(t, td)

	ctx := context.Background()
	// Verify should fail at first
	mustErr(verify(pubKeyPath, imgName, true, nil, ""), t)
	// So should download
	mustErr(download.SignatureCmd(ctx, options.RegistryOptions{}, imgName), t)

	// Now sign the image
	ko := options.KeyOpts{KeyRef: privKeyPath, PassFunc: passFunc}
	so := options.SignOptions{
		Upload: true,
	}
	must(sign.SignCmd(ro, ko, so, []string{imgName}), t)

	// Now verify and download should work!
	must(verify(pubKeyPath, imgName, true, nil, ""), t)
	must(download.SignatureCmd(ctx, options.RegistryOptions{}, imgName), t)

	// Signing again should work just fine...
	must(sign.SignCmd(ro, ko, so, []string{imgName}), t)

	se, err := ociremote.SignedEntity(ref, ociremote.WithRemoteOptions(registryClientOpts(ctx)...))
	must(err, t)
	sigs, err := se.Signatures()
	must(err, t)
	signatures, err := sigs.Get()
	must(err, t)

	if len(signatures) > 1 {
		t.Errorf("expected there to only be one signature, got %v", signatures)
	}
}

func TestKeyURLVerify(t *testing.T) {
	// TODO: re-enable once distroless images are being signed by the new client
	t.Skip()
	// Verify that an image can be verified via key url
	keyRef := "https://raw.githubusercontent.com/GoogleContainerTools/distroless/main/cosign.pub"
	img := "gcr.io/distroless/base:latest"

	must(verify(keyRef, img, true, nil, ""), t)
}

func TestGenerateKeyPairEnvVar(t *testing.T) {
	defer setenv(t, "COSIGN_PASSWORD", "foo")()
	keys, err := cosign.GenerateKeyPair(generate.GetPass)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cosign.LoadPrivateKey(keys.PrivateBytes, []byte("foo")); err != nil {
		t.Fatal(err)
	}
}

func TestGenerateKeyPairK8s(t *testing.T) {
	td := t.TempDir()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(td); err != nil {
		t.Fatal(err)
	}
	defer func() {
		os.Chdir(wd)
	}()
	password := "foo"
	defer setenv(t, "COSIGN_PASSWORD", password)()
	ctx := context.Background()
	name := "cosign-secret"
	namespace := "default"
	if err := kubernetes.KeyPairSecret(ctx, fmt.Sprintf("k8s://%s/%s", namespace, name), generate.GetPass); err != nil {
		t.Fatal(err)
	}
	// make sure the secret actually exists

	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		clientcmd.NewDefaultClientConfigLoadingRules(), nil).ClientConfig()
	if err != nil {
		t.Fatal(err)
	}
	client, err := k8s.NewForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s, err := client.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := s.Data["cosign.password"]; !ok || string(v) != password {
		t.Fatalf("password is incorrect, got %v expected %v", v, "foo")
	}
}

func TestMultipleSignatures(t *testing.T) {
	repo, stop := reg(t)
	defer stop()

	td1 := t.TempDir()
	td2 := t.TempDir()

	imgName := path.Join(repo, "cosign-e2e")

	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	_, priv1, pub1 := keypair(t, td1)
	_, priv2, pub2 := keypair(t, td2)

	// Verify should fail at first for both keys
	mustErr(verify(pub1, imgName, true, nil, ""), t)
	mustErr(verify(pub2, imgName, true, nil, ""), t)

	// Now sign the image with one key
	ko := options.KeyOpts{KeyRef: priv1, PassFunc: passFunc}
	so := options.SignOptions{
		Upload: true,
	}
	must(sign.SignCmd(ro, ko, so, []string{imgName}), t)
	// Now verify should work with that one, but not the other
	must(verify(pub1, imgName, true, nil, ""), t)
	mustErr(verify(pub2, imgName, true, nil, ""), t)

	// Now sign with the other key too
	ko.KeyRef = priv2
	must(sign.SignCmd(ro, ko, so, []string{imgName}), t)

	// Now verify should work with both
	must(verify(pub1, imgName, true, nil, ""), t)
	must(verify(pub2, imgName, true, nil, ""), t)
}

func TestSignBlob(t *testing.T) {
	blob := "someblob"
	td1 := t.TempDir()
	td2 := t.TempDir()
	t.Cleanup(func() {
		os.RemoveAll(td1)
		os.RemoveAll(td2)
	})
	bp := filepath.Join(td1, blob)

	if err := os.WriteFile(bp, []byte(blob), 0644); err != nil {
		t.Fatal(err)
	}

	_, privKeyPath1, pubKeyPath1 := keypair(t, td1)
	_, _, pubKeyPath2 := keypair(t, td2)

	ctx := context.Background()

	ko1 := options.KeyOpts{
		KeyRef: pubKeyPath1,
	}
	ko2 := options.KeyOpts{
		KeyRef: pubKeyPath2,
	}
	// Verify should fail on a bad input
	cmd1 := cliverify.VerifyBlobCmd{
		KeyOpts:    ko1,
		SigRef:     "badsig",
		IgnoreTlog: true,
	}
	cmd2 := cliverify.VerifyBlobCmd{
		KeyOpts:    ko2,
		SigRef:     "badsig",
		IgnoreTlog: true,
	}
	mustErr(cmd1.Exec(ctx, blob), t)
	mustErr(cmd2.Exec(ctx, blob), t)

	// Now sign the blob with one key
	ko := options.KeyOpts{
		KeyRef:   privKeyPath1,
		PassFunc: passFunc,
	}
	sig, err := sign.SignBlobCmd(ro, ko, bp, true, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	// Now verify should work with that one, but not the other
	cmd1.SigRef = string(sig)
	cmd2.SigRef = string(sig)
	must(cmd1.Exec(ctx, bp), t)
	mustErr(cmd2.Exec(ctx, bp), t)
}

func TestSignBlobBundle(t *testing.T) {
	blob := "someblob"
	td1 := t.TempDir()
	t.Cleanup(func() {
		os.RemoveAll(td1)
	})
	bp := filepath.Join(td1, blob)
	bundlePath := filepath.Join(td1, "bundle.sig")

	if err := os.WriteFile(bp, []byte(blob), 0644); err != nil {
		t.Fatal(err)
	}

	_, privKeyPath1, pubKeyPath1 := keypair(t, td1)

	ctx := context.Background()

	ko1 := options.KeyOpts{
		KeyRef:     pubKeyPath1,
		BundlePath: bundlePath,
	}
	// Verify should fail on a bad input
	verifyBlobCmd := cliverify.VerifyBlobCmd{
		KeyOpts:    ko1,
		IgnoreTlog: true,
	}
	mustErr(verifyBlobCmd.Exec(ctx, bp), t)

	// Now sign the blob with one key
	ko := options.KeyOpts{
		KeyRef:           privKeyPath1,
		PassFunc:         passFunc,
		BundlePath:       bundlePath,
		RekorURL:         rekorURL,
		SkipConfirmation: true,
	}
	if _, err := sign.SignBlobCmd(ro, ko, bp, true, "", "", false); err != nil {
		t.Fatal(err)
	}
	// Now verify should work
	must(verifyBlobCmd.Exec(ctx, bp), t)

	// Now we turn on the tlog and sign again
	if _, err := sign.SignBlobCmd(ro, ko, bp, true, "", "", true); err != nil {
		t.Fatal(err)
	}

	// Point to a fake rekor server to make sure offline verification of the tlog entry works
	os.Setenv(serverEnv, "notreal")
	verifyBlobCmd.IgnoreTlog = false
	must(verifyBlobCmd.Exec(ctx, bp), t)
}

func TestSignBlobRFC3161TimestampBundle(t *testing.T) {
	// TSA server needed to create timestamp
	viper.Set("timestamp-signer", "memory")
	viper.Set("timestamp-signer-hash", "sha256")
	apiServer := server.NewRestAPIServer("localhost", 0, []string{"http"}, false, 10*time.Second, 10*time.Second)
	server := httptest.NewServer(apiServer.GetHandler())
	t.Cleanup(server.Close)

	blob := "someblob"
	td1 := t.TempDir()
	t.Cleanup(func() {
		os.RemoveAll(td1)
	})
	bp := filepath.Join(td1, blob)
	bundlePath := filepath.Join(td1, "bundle.sig")
	tsPath := filepath.Join(td1, "rfc3161Timestamp.json")

	if err := os.WriteFile(bp, []byte(blob), 0644); err != nil {
		t.Fatal(err)
	}

	client, err := tsaclient.GetTimestampClient(server.URL)
	if err != nil {
		t.Error(err)
	}

	chain, err := client.Timestamp.GetTimestampCertChain(nil)
	if err != nil {
		t.Fatalf("unexpected error getting timestamp chain: %v", err)
	}

	file, err := os.CreateTemp(os.TempDir(), "tempfile")
	if err != nil {
		t.Fatalf("error creating temp file: %v", err)
	}
	defer os.Remove(file.Name())
	_, err = file.WriteString(chain.Payload)
	if err != nil {
		t.Fatalf("error writing chain payload to temp file: %v", err)
	}

	_, privKeyPath1, pubKeyPath1 := keypair(t, td1)

	ctx := context.Background()

	ko1 := options.KeyOpts{
		KeyRef:               pubKeyPath1,
		BundlePath:           bundlePath,
		RFC3161TimestampPath: tsPath,
		TSACertChainPath:     file.Name(),
	}
	// Verify should fail on a bad input
	verifyBlobCmd := cliverify.VerifyBlobCmd{
		KeyOpts:    ko1,
		IgnoreTlog: true,
	}
	mustErr(verifyBlobCmd.Exec(ctx, bp), t)

	// Now sign the blob with one key
	ko := options.KeyOpts{
		KeyRef:               privKeyPath1,
		PassFunc:             passFunc,
		BundlePath:           bundlePath,
		RFC3161TimestampPath: tsPath,
		TSAServerURL:         server.URL + "/api/v1/timestamp",
		RekorURL:             rekorURL,
		SkipConfirmation:     true,
	}
	if _, err := sign.SignBlobCmd(ro, ko, bp, true, "", "", false); err != nil {
		t.Fatal(err)
	}
	// Now verify should work
	must(verifyBlobCmd.Exec(ctx, bp), t)

	// Now we turn on the tlog and sign again
	if _, err := sign.SignBlobCmd(ro, ko, bp, true, "", "", true); err != nil {
		t.Fatal(err)
	}
	// Point to a fake rekor server to make sure offline verification of the tlog entry works
	verifyBlobCmd.IgnoreTlog = false
	must(verifyBlobCmd.Exec(ctx, bp), t)
}

func TestGenerate(t *testing.T) {
	repo, stop := reg(t)
	defer stop()

	imgName := path.Join(repo, "cosign-e2e")
	_, desc, cleanup := mkimage(t, imgName)
	defer cleanup()

	// Generate the payload for the image, and check the digest.
	b := bytes.Buffer{}
	must(generate.GenerateCmd(context.Background(), options.RegistryOptions{}, imgName, nil, &b), t)
	ss := payload.SimpleContainerImage{}
	must(json.Unmarshal(b.Bytes(), &ss), t)

	equals(desc.Digest.String(), ss.Critical.Image.DockerManifestDigest, t)

	// Now try with some annotations.
	b.Reset()
	a := map[string]interface{}{"foo": "bar"}
	must(generate.GenerateCmd(context.Background(), options.RegistryOptions{}, imgName, a, &b), t)
	must(json.Unmarshal(b.Bytes(), &ss), t)

	equals(desc.Digest.String(), ss.Critical.Image.DockerManifestDigest, t)
	equals(ss.Optional["foo"], "bar", t)
}

func keypair(t *testing.T, td string) (*cosign.KeysBytes, string, string) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(td); err != nil {
		t.Fatal(err)
	}
	defer func() {
		os.Chdir(wd)
	}()
	keys, err := cosign.GenerateKeyPair(passFunc)
	if err != nil {
		t.Fatal(err)
	}

	privKeyPath := filepath.Join(td, "cosign.key")
	if err := os.WriteFile(privKeyPath, keys.PrivateBytes, 0600); err != nil {
		t.Fatal(err)
	}

	pubKeyPath := filepath.Join(td, "cosign.pub")
	if err := os.WriteFile(pubKeyPath, keys.PublicBytes, 0600); err != nil {
		t.Fatal(err)
	}
	return keys, privKeyPath, pubKeyPath
}

func importKeyPair(t *testing.T, td string) (*cosign.KeysBytes, string, string) {

	const validrsa1 = `-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAx5piWVlE62NnZ0UzJ8Z6oKiKOC4dbOZ1HsNhIRtqkM+Oq4G+
25yq6P+0JU/Qvr9veOGEb3R/J9u8JBo+hv2i5X8OtgvP2V2pi6f1s6vK7L0+6uRb
4YTT/UdMshaVf97MgEqbq41Jf/cuvh+3AV0tZ1BpixZg4aXMKpY6HUP69lbsu27o
SUN1myMv7TSgZiV4CYs3l/gkEfpysBptWlcHRuw5RsB+C0RbjRtbJ/5VxmE/vd3M
lafd5t1WSpMb8yf0a84u5NFaXwZ7CweMfXeOddS0yb19ShSuW3PPRadruBM1mq15
js9GfagPxDS75Imcs+fA62lWvHxEujTGjYHxawIDAQABAoIBAH+sgLwmHa9zJfEo
klAe5NFe/QpydN/ziXbkAnzqzH9URC3wD+TpkWj4JoK3Sw635NWtasjf+3XDV9S/
9L7j/g5N91r6sziWcJykEsWaXXKQmm4lI6BdFjwsHyLKz1W7bZOiJXDWLu1rbrqu
DqEQuLoc9WXCKrYrFy0maoXNtfla/1p05kKN0bMigcnnyAQ+xBTwoyco4tkIz5se
IYxorz7qzXrkHQI+knz5BawmNe3ekoSaXUPoLoOR7TRTGsLteL5yukvWAi8S/0rE
gftC+PZCQpoQhSUYq7wXe7RowJ1f+kXb7HsSedOTfTSW1D/pUb/uW+CcRKig42ZI
I9H9TAECgYEA5XGBML6fJyWVqx64sHbUAjQsmQ0RwU6Zo7sqHIEPf6tYVYp7KtzK
KOfi8seOOL5FSy4pjCo11Dzyrh9bn45RNmtjSYTgOnVPSoCfuRNfOcpG+/wCHjYf
EjDvdrCpbg59kVUeaMeBDiyWAlM48HJAn8O7ez2U/iKQCyJmOIwFhSkCgYEA3rSz
Fi1NzqYWxWos4NBmg8iKcQ9SMkmPdgRLAs/WNnZJ8fdgJZwihevkXGytRGJEmav2
GMKRx1g6ey8fjXTQH9WM8X/kJC5fv8wLHnUCH/K3Mcp9CYwn7PFvSnBr4kQoc/el
bURhcF1+/opEC8vNX/Wk3zAG7Xs1PREXlH2SIHMCgYBV/3kgwBH/JkM25EjtO1yz
hsLAivmAruk/SUO7c1RP0fVF+qW3pxHOyztxLALOmeJ3D1JbSubqKf377Zz17O3b
q9yHDdrNjnKtxhAX2n7ytjJs+EQC9t4mf1kB761RpvTBqFnBhCWHHocLUA4jcW9v
cnmu86IIrwO2aKpPv4vCIQKBgHU9gY3qOazRSOmSlJ+hdmZn+2G7pBTvHsQNTIPl
cCrpqNHl3crO4GnKHkT9vVVjuiOAIKU2QNJFwzu4Og8Y8LvhizpTjoHxm9x3iV72
UDELcJ+YrqyJCTe2flUcy96o7Pbn50GXnwgtYD6WAW6IUszyn2ITgYIhu4wzZEt6
s6O7AoGAPTKbRA87L34LMlXyUBJma+etMARIP1zu8bXJ7hSJeMcog8zaLczN7ruT
pGAaLxggvtvuncMuTrG+cdmsR9SafSFKRS92NCxhOUonQ+NP6mLskIGzJZoQ5JvQ
qGzRVIDGbNkrVHM0IsAtHRpC0rYrtZY+9OwiraGcsqUMLwwQdCA=
-----END RSA PRIVATE KEY-----`

	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(td); err != nil {
		t.Fatal(err)
	}
	defer func() {
		os.Chdir(wd)
	}()

	err = os.WriteFile("validrsa1.key", []byte(validrsa1), 0600)
	if err != nil {
		t.Fatal(err)
	}

	keys, err := cosign.ImportKeyPair("validrsa1.key", passFunc)
	if err != nil {
		t.Fatal(err)
	}

	privKeyPath := filepath.Join(td, "import-cosign.key")
	if err := os.WriteFile(privKeyPath, keys.PrivateBytes, 0600); err != nil {
		t.Fatal(err)
	}

	pubKeyPath := filepath.Join(td, "import-cosign.pub")
	if err := os.WriteFile(pubKeyPath, keys.PublicBytes, 0600); err != nil {
		t.Fatal(err)
	}
	return keys, privKeyPath, pubKeyPath

}

func TestUploadDownload(t *testing.T) {
	repo, stop := reg(t)
	defer stop()
	td := t.TempDir()
	ctx := context.Background()

	testCases := map[string]struct {
		signature     string
		signatureType attach.SignatureArgType
		expectedErr   bool
	}{
		"stdin containing signature": {
			signature:     "testsignatureraw",
			signatureType: attach.StdinSignature,
			expectedErr:   false,
		},
		"file containing signature": {
			signature:     "testsignaturefile",
			signatureType: attach.FileSignature,
			expectedErr:   false,
		},
		"raw signature as argument": {
			signature:     "testsignatureraw",
			signatureType: attach.RawSignature,
			expectedErr:   true,
		},
		"empty signature as argument": {
			signature:     "",
			signatureType: attach.RawSignature,
			expectedErr:   true,
		},
	}

	imgName := path.Join(repo, "cosign-e2e")
	for testName, testCase := range testCases {
		t.Run(testName, func(t *testing.T) {
			ref, _, cleanup := mkimage(t, imgName)
			payload := "testpayload"
			payloadPath := mkfile(payload, td, t)
			signature := base64.StdEncoding.EncodeToString([]byte(testCase.signature))
			restoreStdin := func() {}

			var sigRef string
			if testCase.signatureType == attach.FileSignature {
				sigRef = mkfile(signature, td, t)
			} else if testCase.signatureType == attach.StdinSignature {
				sigRef = "-"
				restoreStdin = mockStdin(signature, td, t)
			} else {
				sigRef = signature
			}
			// Upload it!
			err := attach.SignatureCmd(ctx, options.RegistryOptions{}, sigRef, payloadPath, "", "", "", "", imgName)
			if testCase.expectedErr {
				mustErr(err, t)
			} else {
				must(err, t)
			}
			restoreStdin()

			// Now download it!
			se, err := ociremote.SignedEntity(ref, ociremote.WithRemoteOptions(registryClientOpts(ctx)...))
			must(err, t)
			sigs, err := se.Signatures()
			must(err, t)
			signatures, err := sigs.Get()
			must(err, t)

			if testCase.expectedErr {
				if len(signatures) != 0 {
					t.Fatalf("unexpected signatures %d, wanted 0", len(signatures))
				}
			} else {
				if len(signatures) != 1 {
					t.Fatalf("unexpected signatures %d, wanted 1", len(signatures))
				}

				if b64sig, err := signatures[0].Base64Signature(); err != nil {
					t.Fatalf("Base64Signature() = %v", err)
				} else if diff := cmp.Diff(b64sig, signature); diff != "" {
					t.Error(diff)
				}

				if p, err := signatures[0].Payload(); err != nil {
					t.Fatalf("Payload() = %v", err)
				} else if diff := cmp.Diff(p, []byte(payload)); diff != "" {
					t.Error(diff)
				}
			}

			// Now delete it!
			cleanup()
		})
	}
}

func TestSaveLoad(t *testing.T) {
	tests := []struct {
		description     string
		getSignedEntity func(t *testing.T, n string) (name.Reference, *remote.Descriptor, func())
	}{
		{
			description:     "save and load an image",
			getSignedEntity: mkimage,
		},
		{
			description:     "save and load an image index",
			getSignedEntity: mkimageindex,
		},
	}
	for i, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			repo, stop := reg(t)
			defer stop()
			keysDir := t.TempDir()

			imgName := path.Join(repo, fmt.Sprintf("save-load-%d", i))

			_, _, cleanup := test.getSignedEntity(t, imgName)
			defer cleanup()

			_, privKeyPath, pubKeyPath := keypair(t, keysDir)

			ctx := context.Background()
			// Now sign the image and verify it
			ko := options.KeyOpts{KeyRef: privKeyPath, PassFunc: passFunc}
			so := options.SignOptions{
				Upload: true,
			}
			must(sign.SignCmd(ro, ko, so, []string{imgName}), t)
			must(verify(pubKeyPath, imgName, true, nil, ""), t)

			// save the image to a temp dir
			imageDir := t.TempDir()
			must(cli.SaveCmd(ctx, options.SaveOptions{Directory: imageDir}, imgName), t)

			// verify the local image using a local key
			must(verifyLocal(pubKeyPath, imageDir, true, nil, ""), t)

			// load the image from the temp dir into a new image and verify the new image
			imgName2 := path.Join(repo, fmt.Sprintf("save-load-%d-2", i))
			must(cli.LoadCmd(ctx, options.LoadOptions{Directory: imageDir}, imgName2), t)
			must(verify(pubKeyPath, imgName2, true, nil, ""), t)
		})
	}
}

func TestSaveLoadAttestation(t *testing.T) {
	repo, stop := reg(t)
	defer stop()
	td := t.TempDir()

	imgName := path.Join(repo, "save-load")

	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	_, privKeyPath, pubKeyPath := keypair(t, td)

	ctx := context.Background()
	// Now sign the image and verify it
	ko := options.KeyOpts{KeyRef: privKeyPath, PassFunc: passFunc}
	so := options.SignOptions{
		Upload: true,
	}
	must(sign.SignCmd(ro, ko, so, []string{imgName}), t)
	must(verify(pubKeyPath, imgName, true, nil, ""), t)

	// now, append an attestation to the image
	slsaAttestation := `{ "buildType": "x", "builder": { "id": "2" }, "recipe": {} }`
	slsaAttestationPath := filepath.Join(td, "attestation.slsa.json")
	if err := os.WriteFile(slsaAttestationPath, []byte(slsaAttestation), 0600); err != nil {
		t.Fatal(err)
	}

	// Now attest the image
	ko = options.KeyOpts{KeyRef: privKeyPath, PassFunc: passFunc}
	attestCommand := attest.AttestCommand{
		KeyOpts:       ko,
		PredicatePath: slsaAttestationPath,
		PredicateType: "slsaprovenance",
		Timeout:       30 * time.Second,
	}
	must(attestCommand.Exec(ctx, imgName), t)

	// save the image to a temp dir
	imageDir := t.TempDir()
	must(cli.SaveCmd(ctx, options.SaveOptions{Directory: imageDir}, imgName), t)

	// load the image from the temp dir into a new image and verify the new image
	imgName2 := path.Join(repo, "save-load-2")
	must(cli.LoadCmd(ctx, options.LoadOptions{Directory: imageDir}, imgName2), t)
	must(verify(pubKeyPath, imgName2, true, nil, ""), t)
	// Use cue to verify attestation on the new image
	policyPath := filepath.Join(td, "policy.cue")
	verifyAttestation := cliverify.VerifyAttestationCommand{
		KeyRef:     pubKeyPath,
		IgnoreTlog: true,
		MaxWorkers: 10,
	}
	verifyAttestation.PredicateType = "slsaprovenance"
	verifyAttestation.Policies = []string{policyPath}
	// Success case (remote)
	cuePolicy := `predicate: builder: id: "2"`
	if err := os.WriteFile(policyPath, []byte(cuePolicy), 0600); err != nil {
		t.Fatal(err)
	}
	must(verifyAttestation.Exec(ctx, []string{imgName2}), t)
	// Success case (local)
	verifyAttestation.LocalImage = true
	must(verifyAttestation.Exec(ctx, []string{imageDir}), t)
}

func TestAttachSBOM(t *testing.T) {
	repo, stop := reg(t)
	defer stop()
	ctx := context.Background()

	imgName := path.Join(repo, "sbom-image")
	img, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	out := bytes.Buffer{}

	_, errPl := download.SBOMCmd(ctx, options.RegistryOptions{}, options.SBOMDownloadOptions{Platform: "darwin/amd64"}, img.Name(), &out)
	if errPl == nil {
		t.Fatalf("Expected error when passing Platform to single arch image")
	}
	_, err := download.SBOMCmd(ctx, options.RegistryOptions{}, options.SBOMDownloadOptions{}, img.Name(), &out)
	if err == nil {
		t.Fatal("Expected error")
	}
	t.Log(out.String())
	out.Reset()

	// Upload it!
	must(attach.SBOMCmd(ctx, options.RegistryOptions{}, options.RegistryExperimentalOptions{}, "./testdata/bom-go-mod.spdx", "spdx", imgName), t)

	sboms, err := download.SBOMCmd(ctx, options.RegistryOptions{}, options.SBOMDownloadOptions{}, imgName, &out)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(out.String())
	if len(sboms) != 1 {
		t.Fatalf("Expected one sbom, got %d", len(sboms))
	}
	want, err := os.ReadFile("./testdata/bom-go-mod.spdx")
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(string(want), sboms[0]); diff != "" {
		t.Errorf("diff: %s", diff)
	}

	// Generate key pairs to sign the sbom
	td1 := t.TempDir()
	td2 := t.TempDir()
	_, privKeyPath1, pubKeyPath1 := keypair(t, td1)
	_, _, pubKeyPath2 := keypair(t, td2)

	// Verify should fail on a bad input
	mustErr(verify(pubKeyPath1, imgName, true, nil, "sbom"), t)
	mustErr(verify(pubKeyPath2, imgName, true, nil, "sbom"), t)

	// Now sign the sbom with one key
	ko1 := options.KeyOpts{KeyRef: privKeyPath1, PassFunc: passFunc}
	so := options.SignOptions{
		Upload:     true,
		Attachment: "sbom",
	}
	must(sign.SignCmd(ro, ko1, so, []string{imgName}), t)

	// Now verify should work with that one, but not the other
	must(verify(pubKeyPath1, imgName, true, nil, "sbom"), t)
	mustErr(verify(pubKeyPath2, imgName, true, nil, "sbom"), t)
}

func TestAttachSBOM_bom_flag(t *testing.T) {
	repo, stop := reg(t)
	defer stop()
	td := t.TempDir()
	ctx := context.Background()
	bomData, err := os.ReadFile("./testdata/bom-go-mod.spdx")
	must(err, t)

	testCases := map[string]struct {
		bom         string
		bomType     attach.SignatureArgType
		expectedErr bool
	}{
		"stdin containing bom": {
			bom:         string(bomData),
			bomType:     attach.StdinSignature,
			expectedErr: false,
		},
		"file containing bom": {
			bom:         string(bomData),
			bomType:     attach.FileSignature,
			expectedErr: false,
		},
		"raw bom as argument": {
			bom:         string(bomData),
			bomType:     attach.RawSignature,
			expectedErr: true,
		},
		"empty bom as argument": {
			bom:         "",
			bomType:     attach.RawSignature,
			expectedErr: true,
		},
	}

	for testName, testCase := range testCases {
		t.Run(testName, func(t *testing.T) {
			imgName := path.Join(repo, "sbom-image")
			img, _, cleanup := mkimage(t, imgName)
			var sbomRef string
			restoreStdin := func() {}
			if testCase.bomType == attach.FileSignature {
				sbomRef = mkfile(testCase.bom, td, t)
			} else if testCase.bomType == attach.StdinSignature {
				sbomRef = "-"
				restoreStdin = mockStdin(testCase.bom, td, t)
			} else {
				sbomRef = testCase.bom
			}

			out := bytes.Buffer{}
			_, errPl := download.SBOMCmd(ctx, options.RegistryOptions{}, options.SBOMDownloadOptions{Platform: "darwin/amd64"}, img.Name(), &out)
			if errPl == nil {
				t.Fatalf("Expected error when passing Platform to single arch image")
			}
			_, err := download.SBOMCmd(ctx, options.RegistryOptions{}, options.SBOMDownloadOptions{}, img.Name(), &out)
			if err == nil {
				t.Fatal("Expected error")
			}
			t.Log(out.String())
			out.Reset()

			// Upload it!
			err = attach.SBOMCmd(ctx, options.RegistryOptions{}, options.RegistryExperimentalOptions{}, sbomRef, "spdx", imgName)
			restoreStdin()

			if testCase.expectedErr {
				mustErr(err, t)
			} else {
				sboms, err := download.SBOMCmd(ctx, options.RegistryOptions{}, options.SBOMDownloadOptions{}, imgName, &out)
				if err != nil {
					t.Fatal(err)
				}
				t.Log(out.String())
				if len(sboms) != 1 {
					t.Fatalf("Expected one sbom, got %d", len(sboms))
				}
				want, err := os.ReadFile("./testdata/bom-go-mod.spdx")
				if err != nil {
					t.Fatal(err)
				}
				if diff := cmp.Diff(string(want), sboms[0]); diff != "" {
					t.Errorf("diff: %s", diff)
				}
			}

			cleanup()
		})
	}
}

func setenv(t *testing.T, k, v string) func() {
	if err := os.Setenv(k, v); err != nil {
		t.Fatalf("error setting env: %v", err)
	}
	return func() {
		os.Unsetenv(k)
	}
}

func TestTlog(t *testing.T) {
	repo, stop := reg(t)
	defer stop()
	td := t.TempDir()

	imgName := path.Join(repo, "cosign-e2e")

	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	_, privKeyPath, pubKeyPath := keypair(t, td)

	// Verify should fail at first
	mustErr(verify(pubKeyPath, imgName, true, nil, ""), t)

	// Now sign the image without the tlog
	ko := options.KeyOpts{
		KeyRef:   privKeyPath,
		PassFunc: passFunc,
		RekorURL: rekorURL,
	}
	so := options.SignOptions{
		Upload: true,
	}
	must(sign.SignCmd(ro, ko, so, []string{imgName}), t)

	// Now verify should work!
	must(verify(pubKeyPath, imgName, true, nil, ""), t)

	// TODO: priyawadhwa@ to figure out how to add an entry to the tlog without using keyless signing
	// We could add an --upload-tlog flag, but it's a bit weird since we have a --no-upload-tlog flag too right now.

	// Verify shouldn't work since we haven't put anything in it yet.
	// mustErr(verify(pubKeyPath, imgName, true, nil, ""), t)

	// // Sign again with the tlog env var on
	// must(sign.SignCmd(ro, ko, so, []string{imgName}), t)
	// // And now verify works!
	// must(verify(pubKeyPath, imgName, true, nil, ""), t)
}

func TestNoTlog(t *testing.T) {
	repo, stop := reg(t)
	defer stop()
	td := t.TempDir()

	imgName := path.Join(repo, "cosign-e2e")

	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	_, privKeyPath, pubKeyPath := keypair(t, td)

	// Verify should fail at first
	mustErr(verify(pubKeyPath, imgName, true, nil, ""), t)

	// Now sign the image without the tlog
	ko := options.KeyOpts{
		KeyRef:   privKeyPath,
		PassFunc: passFunc,
		RekorURL: rekorURL,
	}
	so := options.SignOptions{
		Upload: true,
	}
	must(sign.SignCmd(ro, ko, so, []string{imgName}), t)

	// Now verify should work!
	must(verify(pubKeyPath, imgName, true, nil, ""), t)

	// TODO: Uncomment once we have a way to tell `cosign verify` that we want to verify with a public key
	// and a tlog entry

	// // Sign again and make sure tlog upload is set to false
	// so = options.SignOptions{
	// 	TlogUpload: false,
	// }
	// must(sign.SignCmd(ro, ko, so, []string{imgName}), t)
	// // And verify it still fails.
	// mustErr(verify(pubKeyPath, imgName, true, nil, ""), t)
}

func TestGetPublicKeyCustomOut(t *testing.T) {
	td := t.TempDir()
	keys, privKeyPath, _ := keypair(t, td)
	ctx := context.Background()

	outFile := "output.pub"
	outPath := filepath.Join(td, outFile)
	outWriter, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE, 0600)
	must(err, t)

	pk := publickey.Pkopts{
		KeyRef: privKeyPath,
	}
	must(publickey.GetPublicKey(ctx, pk, publickey.NamedWriter{Name: outPath, Writer: outWriter}, passFunc), t)

	output, err := os.ReadFile(outPath)
	must(err, t)
	equals(keys.PublicBytes, output, t)
}

func mockStdin(contents, td string, t *testing.T) func() {
	origin := os.Stdin

	p := mkfile(contents, td, t)
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = f

	return func() { os.Stdin = origin }
}

func mkfile(contents, td string, t *testing.T) string {
	f, err := os.CreateTemp(td, "")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write([]byte(contents)); err != nil {
		t.Fatal(err)
	}
	return f.Name()
}

func mkimage(t *testing.T, n string) (name.Reference, *remote.Descriptor, func()) {
	ref, err := name.ParseReference(n, name.WeakValidation)
	if err != nil {
		t.Fatal(err)
	}
	img, err := random.Image(512, 5)
	if err != nil {
		t.Fatal(err)
	}

	regClientOpts := registryClientOpts(context.Background())

	if err := remote.Write(ref, img, regClientOpts...); err != nil {
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
	return ref, remoteImage, cleanup
}

func mkimageindex(t *testing.T, n string) (name.Reference, *remote.Descriptor, func()) {
	ref, err := name.ParseReference(n, name.WeakValidation)
	if err != nil {
		t.Fatal(err)
	}
	ii, err := random.Index(512, 5, 4)
	if err != nil {
		t.Fatal(err)
	}

	regClientOpts := registryClientOpts(context.Background())

	if err := remote.WriteIndex(ref, ii, regClientOpts...); err != nil {
		t.Fatal(err)
	}

	remoteIndex, err := remote.Get(ref, regClientOpts...)
	if err != nil {
		t.Fatal(err)
	}

	cleanup := func() {
		_ = remote.Delete(ref, regClientOpts...)
		ref, _ := ociremote.SignatureTag(ref.Context().Digest(remoteIndex.Descriptor.Digest.String()), ociremote.WithRemoteOptions(regClientOpts...))
		_ = remote.Delete(ref, regClientOpts...)
	}
	return ref, remoteIndex, cleanup
}

func must(err error, t *testing.T) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func mustErr(err error, t *testing.T) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error")
	}
}

func equals(v1, v2 interface{}, t *testing.T) {
	if diff := cmp.Diff(v1, v2); diff != "" {
		t.Error(diff)
	}
}

func reg(t *testing.T) (string, func()) {
	repo := os.Getenv("COSIGN_TEST_REPO")
	if repo != "" {
		return repo, func() {}
	}

	t.Log("COSIGN_TEST_REPO unset, using fake registry")
	r := httptest.NewServer(registry.New())
	u, err := url.Parse(r.URL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host, r.Close
}

func registryClientOpts(ctx context.Context) []remote.Option {
	return []remote.Option{
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithContext(ctx),
	}
}

// If a signature has a bundle, but *not for that signature*, cosign verification should fail.
// This test is pretty long, so here are the basic points:
//  1. Sign image1 with a keypair, store entry in rekor
//  2. Sign image2 with keypair, DO NOT store entry in rekor
//  3. Take the bundle from image1 and store it on the signature in image2
//  4. Verification of image2 should now fail, since the bundle is for a different signature
func TestInvalidBundle(t *testing.T) {
	regName, stop := reg(t)
	defer stop()
	td := t.TempDir()

	img1 := path.Join(regName, "cosign-e2e")

	imgRef, _, cleanup := mkimage(t, img1)
	defer cleanup()

	_, privKeyPath, pubKeyPath := keypair(t, td)

	ctx := context.Background()

	// Sign image1 and store the entry in rekor
	// (we're just using it for its bundle)
	remoteOpts := ociremote.WithRemoteOptions(registryClientOpts(ctx)...)
	ko := options.KeyOpts{KeyRef: privKeyPath, PassFunc: passFunc, RekorURL: rekorURL}
	so := options.SignOptions{
		Upload:           true,
		TlogUpload:       true,
		SkipConfirmation: true,
	}
	must(sign.SignCmd(ro, ko, so, []string{img1}), t)
	// verify image1
	must(verify(pubKeyPath, img1, true, nil, ""), t)
	// extract the bundle from image1
	si, err := ociremote.SignedImage(imgRef, remoteOpts)
	must(err, t)
	imgSigs, err := si.Signatures()
	must(err, t)
	sigs, err := imgSigs.Get()
	must(err, t)
	if l := len(sigs); l != 1 {
		t.Error("expected one signature")
	}
	bund, err := sigs[0].Bundle()
	must(err, t)
	if bund == nil {
		t.Fail()
	}

	// Now, we move on to image2
	// Sign image2 and DO NOT store the entry in rekor
	defer setenv(t, env.VariableExperimental.String(), "0")()
	img2 := path.Join(regName, "unrelated")
	imgRef2, _, cleanup := mkimage(t, img2)
	defer cleanup()
	so = options.SignOptions{
		Upload:     true,
		TlogUpload: false,
	}
	must(sign.SignCmd(ro, ko, so, []string{img2}), t)
	must(verify(pubKeyPath, img2, true, nil, ""), t)

	si2, err := ociremote.SignedEntity(imgRef2, remoteOpts)
	must(err, t)
	sigs2, err := si2.Signatures()
	must(err, t)
	gottenSigs2, err := sigs2.Get()
	must(err, t)
	if len(gottenSigs2) != 1 {
		t.Fatal("there should be one signature")
	}
	sigsTag, err := ociremote.SignatureTag(imgRef2)
	if err != nil {
		t.Fatal(err)
	}

	// At this point, we would mutate the signature to add the bundle annotation
	// since we don't have a function for it at the moment, mock this by deleting the signature
	// and pushing a new signature with the additional bundle annotation
	if err := remote.Delete(sigsTag); err != nil {
		t.Fatal(err)
	}
	mustErr(verify(pubKeyPath, img2, true, nil, ""), t)

	newSig, err := mutate.Signature(gottenSigs2[0], mutate.WithBundle(bund))
	must(err, t)
	si2, err = ociremote.SignedEntity(imgRef2, remoteOpts)
	must(err, t)
	newImage, err := mutate.AttachSignatureToEntity(si2, newSig)
	must(err, t)
	if err := ociremote.WriteSignatures(sigsTag.Repository, newImage); err != nil {
		t.Fatal(err)
	}

	// veriyfing image2 now should fail
	cmd := cliverify.VerifyCommand{
		KeyRef:        pubKeyPath,
		RekorURL:      rekorURL,
		CheckClaims:   true,
		HashAlgorithm: crypto.SHA256,
		MaxWorkers:    10,
	}
	args := []string{img2}
	mustErr(cmd.Exec(context.Background(), args), t)
}

func TestAttestBlobSignVerify(t *testing.T) {
	blob := "someblob"
	predicate := `{ "buildType": "x", "builder": { "id": "2" }, "recipe": {} }`
	predicateType := "slsaprovenance"

	td1 := t.TempDir()
	t.Cleanup(func() {
		os.RemoveAll(td1)
	})

	bp := filepath.Join(td1, blob)
	if err := os.WriteFile(bp, []byte(blob), 0644); err != nil {
		t.Fatal(err)
	}

	anotherBlob := filepath.Join(td1, "another-blob")
	if err := os.WriteFile(anotherBlob, []byte("another-blob"), 0644); err != nil {
		t.Fatal(err)
	}

	predicatePath := filepath.Join(td1, "predicate")
	if err := os.WriteFile(predicatePath, []byte(predicate), 0644); err != nil {
		t.Fatal(err)
	}

	outputSignature := filepath.Join(td1, "signature")

	_, privKeyPath1, pubKeyPath1 := keypair(t, td1)

	ctx := context.Background()
	ko := options.KeyOpts{
		KeyRef: pubKeyPath1,
	}
	blobVerifyAttestationCmd := cliverify.VerifyBlobAttestationCommand{
		KeyOpts:       ko,
		SignaturePath: outputSignature,
		PredicateType: predicateType,
		IgnoreTlog:    true,
		CheckClaims:   true,
	}
	// Verify should fail on a bad input
	mustErr(blobVerifyAttestationCmd.Exec(ctx, bp), t)

	// Now attest the blob with the private key
	ko = options.KeyOpts{
		KeyRef:   privKeyPath1,
		PassFunc: passFunc,
	}
	attestBlobCmd := attest.AttestBlobCommand{
		KeyOpts:         ko,
		PredicatePath:   predicatePath,
		PredicateType:   predicateType,
		OutputSignature: outputSignature,
	}
	must(attestBlobCmd.Exec(ctx, bp), t)

	// Now verify should work
	must(blobVerifyAttestationCmd.Exec(ctx, bp), t)

	// Make sure we fail with the wrong predicate type
	blobVerifyAttestationCmd.PredicateType = "custom"
	mustErr(blobVerifyAttestationCmd.Exec(ctx, bp), t)

	// Make sure we fail with the wrong blob (set the predicate type back)
	blobVerifyAttestationCmd.PredicateType = predicateType
	mustErr(blobVerifyAttestationCmd.Exec(ctx, anotherBlob), t)
}

func TestOffline(t *testing.T) {
	regName, stop := reg(t)
	defer stop()
	td := t.TempDir()

	img1 := path.Join(regName, "cosign-e2e")

	imgRef, _, cleanup := mkimage(t, img1)
	defer cleanup()

	_, privKeyPath, pubKeyPath := keypair(t, td)

	ctx := context.Background()

	// Sign image1 and store the entry in rekor
	ko := options.KeyOpts{KeyRef: privKeyPath, PassFunc: passFunc, RekorURL: rekorURL}
	so := options.SignOptions{
		Upload:           true,
		TlogUpload:       true,
		SkipConfirmation: true,
	}
	must(sign.SignCmd(ro, ko, so, []string{img1}), t)
	// verify image1 online and offline
	must(verify(pubKeyPath, img1, true, nil, ""), t)
	verifyCmd := &cliverify.VerifyCommand{
		KeyRef:      pubKeyPath,
		Offline:     true,
		CheckClaims: true,
		MaxWorkers:  10,
	}
	must(verifyCmd.Exec(ctx, []string{img1}), t)

	// Get signatures
	si, err := ociremote.SignedEntity(imgRef)
	must(err, t)
	sigs, err := si.Signatures()
	must(err, t)
	gottenSigs, err := sigs.Get()
	must(err, t)

	fakeBundle := &bundle.RekorBundle{
		SignedEntryTimestamp: []byte(""),
		Payload: bundle.RekorPayload{
			Body: "",
		},
	}
	newSig, err := mutate.Signature(gottenSigs[0], mutate.WithBundle(fakeBundle))
	must(err, t)

	sigsTag, err := ociremote.SignatureTag(imgRef)
	if err := remote.Delete(sigsTag); err != nil {
		t.Fatal(err)
	}

	si, err = ociremote.SignedEntity(imgRef)
	must(err, t)
	newImage, err := mutate.AttachSignatureToEntity(si, newSig)
	must(err, t)

	mustErr(verify(pubKeyPath, img1, true, nil, ""), t)
	if err := ociremote.WriteSignatures(sigsTag.Repository, newImage); err != nil {
		t.Fatal(err)
	}

	// Confirm offline verification fails
	mustErr(verifyCmd.Exec(ctx, []string{img1}), t)
}
