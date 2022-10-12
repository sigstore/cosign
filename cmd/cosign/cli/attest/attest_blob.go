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

package attest

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/pkg/cosign/attestation"
	"github.com/sigstore/cosign/pkg/types"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
)

// nolint
func AttestBlobCmd(ctx context.Context, ko options.KeyOpts, artifactPath string, artifactHash string, certPath string, certChainPath string, predicatePath string, predicateType string, timeout time.Duration, outputSignature string) error {
	// TODO: Add in experimental keyless mode
	if !options.OneOf(ko.KeyRef, ko.Sk) {
		return &options.KeyParseError{}
	}

	var artifact []byte
	var hexDigest string
	var err error

	if artifactHash == "" {
		if artifactPath == "-" {
			artifact, err = io.ReadAll(os.Stdin)
		} else {
			fmt.Fprintln(os.Stderr, "Using payload from:", artifactPath)
			artifact, err = os.ReadFile(filepath.Clean(artifactPath))
		}
		if err != nil {
			return err
		}
	}

	sv, err := sign.SignerFromKeyOpts(ctx, certPath, certChainPath, ko)
	if err != nil {
		return errors.Wrap(err, "getting signer")
	}
	defer sv.Close()

	if timeout != 0 {
		var cancelFn context.CancelFunc
		ctx, cancelFn = context.WithTimeout(ctx, timeout)
		defer cancelFn()
	}

	if artifactHash == "" {
		digest, _, err := signature.ComputeDigestForSigning(bytes.NewReader(artifact), crypto.SHA256, []crypto.Hash{crypto.SHA256, crypto.SHA384})
		if err != nil {
			return err
		}
		hexDigest = strings.ToLower(hex.EncodeToString(digest))
	} else {
		hexDigest = artifactHash
	}
	wrapped := dsse.WrapSigner(sv, types.IntotoPayloadType)

	fmt.Fprintln(os.Stderr, "Using payload from:", predicatePath)
	predicate, err := os.Open(predicatePath)
	if err != nil {
		return err
	}
	defer predicate.Close()

	base := path.Base(artifactPath)

	sh, err := attestation.GenerateStatement(attestation.GenerateOpts{
		Predicate: predicate,
		Type:      predicateType,
		Digest:    hexDigest,
		Repo:      base,
	})
	if err != nil {
		return err
	}

	payload, err := json.Marshal(sh)
	if err != nil {
		return err
	}

	sig, err := wrapped.SignMessage(bytes.NewReader(payload), signatureoptions.WithContext(ctx))
	if err != nil {
		return errors.Wrap(err, "signing")
	}

	sig = []byte(base64.StdEncoding.EncodeToString(sig))
	if outputSignature != "" {
		if err := os.WriteFile(outputSignature, sig, 0600); err != nil {
			return fmt.Errorf("create signature file: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Signature written in %s\n", outputSignature)
	} else {
		fmt.Fprintln(os.Stdout, string(sig))
	}

	return nil
}
