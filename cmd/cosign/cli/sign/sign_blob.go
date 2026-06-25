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

package sign

import (
	"context"
	"crypto"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"net/http"

	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/signcommon"
	internal "github.com/sigstore/cosign/v3/internal/pkg/cosign"
	"github.com/sigstore/cosign/v3/internal/pkg/cosign/tsa/client"
	"github.com/sigstore/cosign/v3/internal/ui"
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
func SignBlobCmd(ctx context.Context, ro *options.RootOptions, ko options.KeyOpts, payloadPath, certPath, certChainPath string) error {
	var payload internal.HashReader

	ctx, cancel := context.WithTimeout(ctx, ro.Timeout)
	defer cancel()

	if ko.SigningConfig == nil {
		ko.SigningConfig = signcommon.NewEmptySigningConfig()
	}

	shouldUpload, err := signcommon.ShouldUploadToTlog(ctx, ko, nil, len(ko.SigningConfig.RekorLogURLs()) > 0)
	if err != nil {
		return fmt.Errorf("should upload to tlog: %w", err)
	}

	if !shouldUpload {
		// To maintain backwards compatibility with older cosign versions,
		// we do not use ed25519ph for ed25519 keys when the signatures are not
		// uploaded to the Tlog.
		ko.DefaultLoadOptions = &[]signature.LoadOption{}
	}

	keypair, certBytes, idToken, err := signcommon.GetKeypairAndToken(ctx, ko, certPath, certChainPath)
	if err != nil {
		return fmt.Errorf("getting keypair and token: %w", err)
	}
	if closer, ok := keypair.(interface{ Close() }); ok {
		defer closer.Close()
	}

	hashFunction := signcommon.ProtoHashAlgoToHash(keypair.GetHashAlgorithm())
	payload, closePayload, err := getPayload(ctx, payloadPath, hashFunction)
	if err != nil {
		return fmt.Errorf("getting payload: %w", err)
	}
	defer closePayload()

	data, err := io.ReadAll(&payload)
	if err != nil {
		return fmt.Errorf("reading payload: %w", err)
	}
	content := &sign.PlainData{
		Data: data,
	}

	var tsaClientTransport http.RoundTripper
	if ko.TSAClientCACert != "" || (ko.TSAClientCert != "" && ko.TSAClientKey != "") {
		tsaClientTransport, err = client.GetHTTPTransport(ko.TSAClientCACert, ko.TSAClientCert, ko.TSAClientKey, ko.TSAServerName, 30*time.Second)
		if err != nil {
			return fmt.Errorf("getting TSA client transport: %w", err)
		}
	}
	signOpts := cbundle.SignOptions{TSAClientTransport: tsaClientTransport}
	bundleBytes, err := cbundle.SignData(ctx, content, keypair, idToken, certBytes, ko.SigningConfig, ko.TrustedMaterial, signOpts)
	if err != nil {
		return fmt.Errorf("signing bundle: %w", err)
	}

	if err := os.WriteFile(ko.BundlePath, bundleBytes, 0600); err != nil {
		return fmt.Errorf("create bundle file: %w", err)
	}
	ui.Infof(ctx, "Wrote bundle to file %s", ko.BundlePath)
	return nil
}
