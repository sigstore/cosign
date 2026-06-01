// Copyright 2026 The Sigstore Authors.
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
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/sigstore/cosign/v3/cmd/cosign/cli/sign/privacy"
	internal "github.com/sigstore/cosign/v3/internal/pkg/cosign"
	"github.com/sigstore/cosign/v3/internal/ui"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	cbundle "github.com/sigstore/cosign/v3/pkg/cosign/bundle"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore/pkg/signature"
)

func getPayload(ctx context.Context, payloadPath string, hashFunction crypto.Hash) (internal.HashReader, func() error, error) {
	if payloadPath == "-" {
		return internal.NewHashReader(os.Stdin, hashFunction), func() error { return nil }, nil
	}
	ui.Infof(ctx, "Using payload from: %s", payloadPath)
	f, err := os.Open(filepath.Clean(payloadPath))
	if err != nil {
		return internal.HashReader{}, nil, err
	}
	return internal.NewHashReader(f, hashFunction), f.Close, nil
}

// nolint
func signBundle(ctx context.Context, ro *RootOptions, ko KeyOpts, payloadPath, certPath, certChainPath string, tlogUpload bool, inToto bool) error {
	var payload internal.HashReader

	ctx, cancel := context.WithTimeout(ctx, ro.Timeout)
	defer cancel()

	var shouldUpload bool
	var err error

	if ko.SigningConfig == nil {
		err = confirmTlogUpload(ctx, ko, tlogUpload)
		if err != nil {
			return fmt.Errorf("upload to tlog: %w", err)
		}

		ko.SigningConfig, err = cosign.SigningConfig()
		if err != nil {
			return fmt.Errorf("getting signing config from TUF: %w", err)
		}

		if !tlogUpload {
			ko.SigningConfig = ko.SigningConfig.WithRekorLogURLs()
		}
		shouldUpload = tlogUpload
	} else {
		shouldUpload = len(ko.SigningConfig.RekorLogURLs()) > 0
	}

	if !shouldUpload {
		// To maintain backwards compatibility with older cosign versions,
		// we do not use ed25519ph for ed25519 keys when the signatures are not
		// uploaded to the Tlog.
		ko.DefaultLoadOptions = &[]signature.LoadOption{}
	}

	keypair, certBytes, idToken, err := getKeypairAndToken(ctx, ko, certPath, certChainPath)
	if err != nil {
		return fmt.Errorf("getting keypair and token: %w", err)
	}
	if closer, ok := keypair.(interface{ Close() }); ok {
		defer closer.Close()
	}

	hashFunction := protoHashAlgoToHash(keypair.GetHashAlgorithm())
	payload, closePayload, err := getPayload(ctx, payloadPath, hashFunction)
	if err != nil {
		return fmt.Errorf("getting payload: %w", err)
	}
	defer closePayload()

	data, err := io.ReadAll(&payload)
	if err != nil {
		return fmt.Errorf("reading payload: %w", err)
	}
	var content sign.Content
	if inToto {
		content = &sign.DSSEData{
			Data:        data,
			PayloadType: "application/vnd.in-toto+json",
		}
	} else {
		content = &sign.PlainData{
			Data: data,
		}
	}

	bundleBytes, err := cbundle.SignData(ctx, content, keypair, idToken, certBytes, ko.SigningConfig, ko.TrustedMaterial, cbundle.SignOptions{})
	if err != nil {
		return fmt.Errorf("signing bundle: %w", err)
	}

	if err := os.WriteFile(ko.BundlePath, bundleBytes, 0600); err != nil {
		return fmt.Errorf("create bundle file: %w", err)
	}
	ui.Infof(ctx, "Wrote bundle to file %s", ko.BundlePath)
	return nil
}

func confirmTlogUpload(ctx context.Context, ko KeyOpts, tlogUpload bool) error {
	if !tlogUpload {
		return nil
	}

	var statementErr error
	privacy.StatementOnce.Do(func() {
		ui.Infof(ctx, privacy.Statement)
		ui.Infof(ctx, privacy.StatementConfirmation)
		if !ko.SkipConfirmation {
			if err := ui.ConfirmContinue(ctx); err != nil {
				statementErr = err
			}
		}
	})

	return statementErr
}
