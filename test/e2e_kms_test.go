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
	"os"
	"path"
	"testing"

	"github.com/sigstore/cosign/v3/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/v3/pkg/cosign/env"
	_ "github.com/sigstore/sigstore/pkg/signature/kms/hashivault"
)

const (
	rekorURLVar = "REKOR_URL"
	testKMSVar  = "TEST_KMS"
	defaultKMS  = "hashivault://transit"
)

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

	// Verify should fail at first
	mustErr(verify(pubKey, imgName, true, nil, "", false), t)

	rekorURL := os.Getenv(rekorURLVar)

	must(downloadAndSetEnv(t, rekorURL+"/api/v1/log/publicKey", env.VariableSigstoreRekorPublicKey.String(), td), t)

	// Now sign and verify with the KMS key
	ko := options.KeyOpts{
		KeyRef:           privKey,
		RekorURL:         rekorURL,
		RekorVersion:     1,
		SkipConfirmation: true,
	}
	so := options.SignOptions{
		Upload:     true,
		TlogUpload: true,
	}
	must(sign.SignCmd(t.Context(), ro, ko, so, []string{imgName}), t)
	must(verify(pubKey, imgName, true, nil, "", false), t)

	// Sign and verify with annotations
	mustErr(verify(pubKey, imgName, true, map[string]any{"foo": "bar"}, "", false), t)
	soAnno := options.SignOptions{
		Upload:     true,
		TlogUpload: true,
		AnnotationOptions: options.AnnotationOptions{
			Annotations: []string{"foo=bar"},
		},
	}
	must(sign.SignCmd(t.Context(), ro, ko, soAnno, []string{imgName}), t)
	must(verify(pubKey, imgName, true, map[string]any{"foo": "bar"}, "", false), t)

	// Store signatures in a different repo
	t.Setenv("COSIGN_REPOSITORY", path.Join(repo, "subbedrepo"))
	must(sign.SignCmd(t.Context(), ro, ko, so, []string{imgName}), t)
	must(verify(pubKey, imgName, true, nil, "", false), t)
	os.Unsetenv("COSIGN_REPOSITORY")
}
