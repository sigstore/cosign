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

//go:build e2e && kms

package test

import (
	"context"
	"crypto"
	"os"
	"path"
	"testing"
	"time"

	"github.com/sigstore/cosign/v3/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/initialize"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/sign"
	cliverify "github.com/sigstore/cosign/v3/cmd/cosign/cli/verify"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	sigs "github.com/sigstore/cosign/v3/pkg/signature"
	prototrustroot "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
	_ "github.com/sigstore/sigstore/pkg/signature/kms/hashivault"
)

const (
	rekorURLVar = "REKOR_URL"
	testKMSVar  = "TEST_KMS"
	defaultKMS  = "hashivault://transit"
)

func verifyKMS(keyRef, imageRef string, annotations map[string]any) error {
	cmd := cliverify.VerifyCommand{
		KeyRef:        keyRef,
		CheckClaims:   true,
		Annotations:   sigs.AnnotationsMap{Annotations: annotations},
		HashAlgorithm: crypto.SHA256,
		MaxWorkers:    10,
		CommonVerifyOptions: options.CommonVerifyOptions{
			NewBundleFormat: true,
		},
	}
	return cmd.Exec(context.Background(), []string{imageRef})
}

func TestSecretsKMS(t *testing.T) {
	ctx := context.Background()

	repo, stop := reg(t)
	defer stop()
	td := t.TempDir()

	imgName := path.Join(repo, "cosign-kms-e2e")
	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	kms := os.Getenv(testKMSVar)
	if kms == "" {
		kms = defaultKMS
	}

	prefix := path.Join(td, "test-kms")

	must(generate.GenerateKeyPairCmd(ctx, kms, prefix, nil), t)

	pubKey := prefix + ".pub"
	privKey := kms

	tufLocalCache := t.TempDir()
	t.Setenv("TUF_ROOT", tufLocalCache)
	rootPath := os.Getenv("TUF_ROOT_JSON")
	mirror := os.Getenv("TUF_MIRROR")
	must(initialize.DoInitialize(ctx, rootPath, mirror), t)

	// Verify should fail at first
	mustErr(verifyKMS(pubKey, imgName, nil), t)

	rekorURL := os.Getenv(rekorURLVar)
	rekorServices := []root.Service{
		{
			URL:                 rekorURL,
			MajorAPIVersion:     2,
			ValidityPeriodStart: time.Now().Add(-time.Hour),
		},
	}
	rekorConfig := root.ServiceConfiguration{
		Selector: prototrustroot.ServiceSelector_ANY,
		Count:    1,
	}
	signingConfig, err := root.NewSigningConfig(
		root.SigningConfigMediaType02,
		nil,
		nil,
		rekorServices,
		rekorConfig,
		nil,
		root.ServiceConfiguration{},
	)
	must(err, t)

	trustedMaterial, err := cosign.TrustedRoot()
	must(err, t)

	// Now sign and verify with the KMS key
	ko := options.KeyOpts{
		KeyRef:           privKey,
		SigningConfig:    signingConfig,
		TrustedMaterial:  trustedMaterial,
		SkipConfirmation: true,
		NewBundleFormat:  true,
	}
	so := options.SignOptions{
		Upload:          true,
		TlogUpload:      true,
		NewBundleFormat: true,
	}
	must(sign.SignCmd(t.Context(), ro, ko, so, []string{imgName}), t)
	must(verifyKMS(pubKey, imgName, nil), t)

	// Sign and verify with annotations
	mustErr(verifyKMS(pubKey, imgName, map[string]any{"foo": "bar"}), t)
	soAnno := options.SignOptions{
		Upload:          true,
		TlogUpload:      true,
		NewBundleFormat: true,
		AnnotationOptions: options.AnnotationOptions{
			Annotations: []string{"foo=bar"},
		},
	}
	must(sign.SignCmd(t.Context(), ro, ko, soAnno, []string{imgName}), t)
	must(verifyKMS(pubKey, imgName, map[string]any{"foo": "bar"}), t)

	// Store signatures in a different repo
	t.Setenv("COSIGN_REPOSITORY", path.Join(repo, "subbedrepo"))
	must(sign.SignCmd(t.Context(), ro, ko, so, []string{imgName}), t)
	must(verifyKMS(pubKey, imgName, nil), t)
	os.Unsetenv("COSIGN_REPOSITORY")
}
