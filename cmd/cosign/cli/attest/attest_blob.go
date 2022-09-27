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
	"github.com/sigstore/cosign/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/attestation"
	cbundle "github.com/sigstore/cosign/pkg/cosign/bundle"
	"github.com/sigstore/cosign/pkg/types"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
)

// nolint
func AttestBlobCmd(ctx context.Context, ko options.KeyOpts, artifactPath string, artifactHash string, certPath string, certChainPath string, noUpload bool, predicatePath string, force bool, predicateType string, replace bool, timeout time.Duration) error {
	// A key file or token is required unless we're in experimental mode!
	if options.EnableExperimental() {
		if options.NOf(ko.KeyRef, ko.Sk) > 1 {
			return &options.KeyParseError{}
		}
	} else {
		if !options.OneOf(ko.KeyRef, ko.Sk) {
			return &options.KeyParseError{}
		}
	}

	var artifact []byte
	var hexDigest string
	var rekorBytes []byte
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

	// Check whether we should be uploading to the transparency log
	signedPayload := cosign.LocalSignedPayload{}
	if options.EnableExperimental() {
		rekorBytes, err := sv.Bytes(ctx)
		if err != nil {
			return err
		}
		rekorClient, err := rekor.NewClient(ko.RekorURL)
		if err != nil {
			return err
		}
		entry, err := cosign.TLogUploadInTotoAttestation(ctx, rekorClient, sig, rekorBytes)
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "tlog entry created with index:", *entry.LogIndex)
		signedPayload.Bundle = cbundle.EntryToBundle(entry)
	}

	// if bundle is specified, just do that and ignore the rest
	if ko.BundlePath != "" {
		signedPayload.Base64Signature = base64.StdEncoding.EncodeToString(sig)
		signedPayload.Cert = base64.StdEncoding.EncodeToString(rekorBytes)

		contents, err := json.Marshal(signedPayload)
		if err != nil {
			return err
		}
		if err := os.WriteFile(ko.BundlePath, contents, 0600); err != nil {
			return fmt.Errorf("create bundle file: %w", err)
		}
		fmt.Printf("Bundle wrote in the file %s\n", ko.BundlePath)
	}

	// Print signature and certificate
	// TODO: Write the signature and certificate to file if specified via flag
	fmt.Println("Signature:")
	sig = []byte(base64.StdEncoding.EncodeToString(sig))
	fmt.Println(string(sig))

	if rekorBytes != nil {
		fmt.Println("Cert:")
		fmt.Println(string(rekorBytes))
	}

	return nil
}
