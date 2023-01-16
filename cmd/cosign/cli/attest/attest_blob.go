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
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/v2/internal/pkg/cosign/tsa"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/cosign/attestation"
	cbundle "github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v2/pkg/types"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
	tsaclient "github.com/sigstore/timestamp-authority/pkg/client"
)

// nolint
type AttestBlobCommand struct {
	options.KeyOpts

	ArtifactHash string

	PredicatePath string
	PredicateType string

	TlogUpload bool
	Timeout    time.Duration

	OutputSignature   string
	OutputAttestation string
	OutputCertificate string
}

// nolint
func (c *AttestBlobCommand) Exec(ctx context.Context, artifactPath string) error {
	// We can't have both a key and a security key
	if options.NOf(c.KeyRef, c.Sk) > 1 {
		return &options.KeyParseError{}
	}

	if c.Timeout != 0 {
		var cancelFn context.CancelFunc
		ctx, cancelFn = context.WithTimeout(ctx, c.Timeout)
		defer cancelFn()
	}

	if c.TSAServerURL != "" && c.RFC3161TimestampPath == "" {
		return errors.New("expected an rfc3161-timestamp path when using a TSA server")
	}

	var artifact []byte
	var hexDigest string
	var err error

	if c.ArtifactHash == "" {
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

	if c.ArtifactHash == "" {
		digest, _, err := signature.ComputeDigestForSigning(bytes.NewReader(artifact), crypto.SHA256, []crypto.Hash{crypto.SHA256, crypto.SHA384})
		if err != nil {
			return err
		}
		hexDigest = strings.ToLower(hex.EncodeToString(digest))
	} else {
		hexDigest = c.ArtifactHash
	}

	fmt.Fprintln(os.Stderr, "Using predicate from:", c.PredicatePath)
	predicate, err := os.Open(c.PredicatePath)
	if err != nil {
		return err
	}
	defer predicate.Close()

	sv, err := sign.SignerFromKeyOpts(ctx, c.KeyOpts)
	if err != nil {
		return fmt.Errorf("getting signer: %w", err)
	}
	defer sv.Close()
	wrapped := dsse.WrapSigner(sv, types.IntotoPayloadType)

	base := path.Base(artifactPath)

	sh, err := attestation.GenerateStatement(attestation.GenerateOpts{
		Predicate: predicate,
		Type:      c.PredicateType,
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

	var rfc3161Timestamp *cbundle.RFC3161Timestamp
	if c.TSAServerURL != "" {
		clientTSA, err := tsaclient.GetTimestampClient(c.TSAServerURL)
		if err != nil {
			return fmt.Errorf("failed to create TSA client: %w", err)
		}
		respBytes, err := tsa.GetTimestampedSignature(sig, clientTSA)
		if err != nil {
			return err
		}
		rfc3161Timestamp = cbundle.TimestampToRFC3161Timestamp(respBytes)
		// TODO: Consider uploading RFC3161 TS to Rekor

		if rfc3161Timestamp == nil {
			return fmt.Errorf("rfc3161 timestamp is nil")
		}
		ts, err := json.Marshal(rfc3161Timestamp)
		if err != nil {
			return err
		}
		if err := os.WriteFile(c.RFC3161TimestampPath, ts, 0600); err != nil {
			return fmt.Errorf("create RFC3161 timestamp file: %w", err)
		}
		fmt.Fprintln(os.Stderr, "RFC3161 timestamp bundle written to file ", c.RFC3161TimestampPath)
	}

	rekorBytes, err := sv.Bytes(ctx)
	if err != nil {
		return err
	}
	shouldUpload, err := sign.ShouldUploadToTlog(ctx, c.KeyOpts, nil, c.TlogUpload)
	if err != nil {
		return fmt.Errorf("upload to tlog: %w", err)
	}
	signedPayload := cosign.LocalSignedPayload{}
	if shouldUpload {
		rekorClient, err := rekor.NewClient(c.RekorURL)
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

	if c.BundlePath != "" {
		signedPayload.Base64Signature = base64.StdEncoding.EncodeToString(sig)
		signedPayload.Cert = base64.StdEncoding.EncodeToString(rekorBytes)

		contents, err := json.Marshal(signedPayload)
		if err != nil {
			return err
		}
		if err := os.WriteFile(c.BundlePath, contents, 0600); err != nil {
			return fmt.Errorf("create bundle file: %w", err)
		}
		fmt.Fprintln(os.Stderr, "Bundle wrote in the file ", c.BundlePath)
	}

	if c.OutputSignature != "" {
		if err := os.WriteFile(c.OutputSignature, sig, 0600); err != nil {
			return fmt.Errorf("create signature file: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Signature written in %s\n", c.OutputSignature)
	} else {
		fmt.Fprintln(os.Stdout, string(sig))
	}

	if c.OutputAttestation != "" {
		if err := os.WriteFile(c.OutputAttestation, payload, 0600); err != nil {
			return fmt.Errorf("create signature file: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Attestation written in %s\n", c.OutputAttestation)
	}

	if c.OutputCertificate != "" {
		signer, err := sv.Bytes(ctx)
		if err != nil {
			return fmt.Errorf("error getting signer: %w", err)
		}
		cert, err := cryptoutils.UnmarshalCertificatesFromPEM(signer)
		// signer is a certificate
		if err != nil {
			fmt.Fprintln(os.Stderr, "Could not output signer certificate. Was a certificate used? ", err)
			return nil

		}
		if len(cert) != 1 {
			fmt.Fprintln(os.Stderr, "Could not output signer certificate. Expected a single certificate")
			return nil
		}
		bts := signer
		if err := os.WriteFile(c.OutputCertificate, bts, 0600); err != nil {
			return fmt.Errorf("create certificate file: %w", err)
		}
		fmt.Fprintln(os.Stderr, "Certificate written to file ", c.OutputCertificate)
	}

	return nil
}
