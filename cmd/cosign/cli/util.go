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

package cli

import (
	"context"
	"crypto"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms"
)

const (
	ExperimentalEnv = "COSIGN_EXPERIMENTAL"
	repoEnv         = "COSIGN_REPOSITORY"
)

func EnableExperimental() bool {
	if b, err := strconv.ParseBool(os.Getenv(ExperimentalEnv)); err == nil {
		return b
	}
	return false
}

func TargetRepositoryForImage(img name.Reference) (name.Repository, error) {
	wantRepo := os.Getenv(repoEnv)
	if wantRepo == "" {
		return img.Context(), nil
	}
	return name.NewRepository(wantRepo)
}

func LoadPublicKey(ctx context.Context, keyRef string) (verifier signature.Verifier, err error) {
	// The key could be plaintext, in a file, at a URL, or in KMS.
	if kmsKey, err := kms.Get(ctx, keyRef, crypto.SHA256); err == nil {
		// KMS specified
		return kmsKey, nil
	}

	var raw []byte

	if strings.HasPrefix(keyRef, "http://") || strings.HasPrefix(keyRef, "https://") {
		// key-url specified
		// #nosec G107
		resp, err := http.Get(keyRef)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		raw, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
	} else if raw, err = ioutil.ReadFile(filepath.Clean(keyRef)); err != nil {
		return nil, err
	}

	// PEM encoded file.
	ed, err := cosign.PemToECDSAKey(raw)
	if err != nil {
		return nil, errors.Wrap(err, "pem to ecdsa")
	}
	return signature.LoadECDSAVerifier(ed, crypto.SHA256)
}
