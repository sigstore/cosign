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
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	intotov1 "github.com/in-toto/attestation/go/v1"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/v2/internal/pkg/cosign/tsa"
	tsaclient "github.com/sigstore/cosign/v2/internal/pkg/cosign/tsa/client"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/cosign/attestation"
	cbundle "github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v2/pkg/types"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	sigstoredsse "github.com/sigstore/sigstore/pkg/signature/dsse"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
	"google.golang.org/protobuf/encoding/protojson"
)

// nolint
type AttestBlobCommand struct {
	options.KeyOpts
	CertPath      string
	CertChainPath string

	ArtifactHash string

	StatementPath string
	PredicatePath string
	PredicateType string

	TlogUpload bool
	Timeout    time.Duration

	OutputSignature   string
	OutputAttestation string
	OutputCertificate string

	RekorEntryType string
}

// nolint
func (c *AttestBlobCommand) Exec(ctx context.Context, artifactPath string) error {
	// We can't have both a key and a security key
	if options.NOf(c.KeyRef, c.Sk) > 1 {
		return &options.KeyParseError{}
	}

	if options.NOf(c.PredicatePath, c.StatementPath) != 1 {
		return fmt.Errorf("one of --predicate or --statement must be set")
	}

	if c.RekorEntryType != "dsse" && c.RekorEntryType != "intoto" {
		return fmt.Errorf("unknown value for rekor-entry-type")
	}

	if c.Timeout != 0 {
		var cancelFn context.CancelFunc
		ctx, cancelFn = context.WithTimeout(ctx, c.Timeout)
		defer cancelFn()
	}

	if c.TSAServerURL != "" && c.RFC3161TimestampPath == "" && !c.NewBundleFormat {
		return errors.New("expected either new bundle or an rfc3161-timestamp path when using a TSA server")
	}

	sv, err := sign.SignerFromKeyOpts(ctx, c.CertPath, c.CertChainPath, c.KeyOpts)
	if err != nil {
		return fmt.Errorf("getting signer: %w", err)
	}
	defer sv.Close()
	wrapped := sigstoredsse.WrapSigner(sv, types.IntotoPayloadType)

	base := path.Base(artifactPath)

	var payload []byte

	if c.StatementPath != "" {
		fmt.Fprintln(os.Stderr, "Using statement from:", c.StatementPath)
		payload, err = os.ReadFile(filepath.Clean(c.StatementPath))
		if err != nil {
			return fmt.Errorf("could not read statement: %w", err)
		}
		if _, err := validateStatement(payload); err != nil {
			return fmt.Errorf("invalid statement: %w", err)
		}

	} else {
		var artifact []byte
		var hexDigest string
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
		predicate, err := predicateReader(c.PredicatePath)
		if err != nil {
			return fmt.Errorf("getting predicate reader: %w", err)
		}
		defer predicate.Close()
		sh, err := attestation.GenerateStatement(attestation.GenerateOpts{
			Predicate: predicate,
			Type:      c.PredicateType,
			Digest:    hexDigest,
			Repo:      base,
		})
		if err != nil {
			return err
		}
		payload, err = json.Marshal(sh)
		if err != nil {
			return err
		}
	}

	sig, err := wrapped.SignMessage(bytes.NewReader(payload), signatureoptions.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("signing: %w", err)
	}

	var rfc3161Timestamp *cbundle.RFC3161Timestamp
	var timestampBytes []byte
	var tsaPayload []byte
	var rekorEntry *models.LogEntryAnon

	if c.KeyOpts.TSAServerURL != "" {
		tc := tsaclient.NewTSAClient(c.KeyOpts.TSAServerURL)
		if c.TSAClientCert != "" {
			tc = tsaclient.NewTSAClientMTLS(c.KeyOpts.TSAServerURL,
				c.KeyOpts.TSAClientCACert,
				c.KeyOpts.TSAClientCert,
				c.KeyOpts.TSAClientKey,
				c.KeyOpts.TSAServerName,
			)
		}
		// We need to decide what signature to send to the timestamp authority.
		//
		// Historically, cosign sent `sig`, which is the entire JSON DSSE
		// Envelope. However, when sigstore clients are verifying a bundle they
		// will use the DSSE Sig field, so we choose what signature to send to
		// the timestamp authority based on our output format.
		if c.NewBundleFormat {
			tsaPayload, err = getEnvelopeSigBytes(sig)
			if err != nil {
				return err
			}
		} else {
			tsaPayload = sig
		}
		timestampBytes, err = tsa.GetTimestampedSignature(tsaPayload, tc)
		if err != nil {
			return err
		}
		rfc3161Timestamp = cbundle.TimestampToRFC3161Timestamp(timestampBytes)
		// TODO: Consider uploading RFC3161 TS to Rekor

		if rfc3161Timestamp == nil {
			return fmt.Errorf("rfc3161 timestamp is nil")
		}

		if c.RFC3161TimestampPath != "" {
			ts, err := json.Marshal(rfc3161Timestamp)
			if err != nil {
				return err
			}
			if err := os.WriteFile(c.RFC3161TimestampPath, ts, 0600); err != nil {
				return fmt.Errorf("create RFC3161 timestamp file: %w", err)
			}
			fmt.Fprintln(os.Stderr, "RFC3161 timestamp bundle written to file ", c.RFC3161TimestampPath)
		}
	}

	signer, err := sv.Bytes(ctx)
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
		if c.RekorEntryType == "intoto" {
			rekorEntry, err = cosign.TLogUploadInTotoAttestation(ctx, rekorClient, sig, signer)
		} else {
			rekorEntry, err = cosign.TLogUploadDSSEEnvelope(ctx, rekorClient, sig, signer)
		}

		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "tlog entry created with index:", *rekorEntry.LogIndex)
		signedPayload.Bundle = cbundle.EntryToBundle(rekorEntry)
	}

	if c.BundlePath != "" {
		var contents []byte
		if c.NewBundleFormat {
			contents, err = makeNewBundle(sv, rekorEntry, payload, sig, signer, timestampBytes)
			if err != nil {
				return err
			}
		} else {
			signedPayload.Base64Signature = base64.StdEncoding.EncodeToString(sig)
			signedPayload.Cert = base64.StdEncoding.EncodeToString(signer)

			contents, err = json.Marshal(signedPayload)
			if err != nil {
				return err
			}
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

func makeNewBundle(sv *sign.SignerVerifier, rekorEntry *models.LogEntryAnon, payload, sig, signer, timestampBytes []byte) ([]byte, error) {
	// Determine if signature is certificate or not
	var hint string
	var rawCert []byte

	cert, err := cryptoutils.UnmarshalCertificatesFromPEM(signer)
	if err != nil || len(cert) == 0 {
		pubKey, err := sv.PublicKey()
		if err != nil {
			return nil, err
		}
		pkixPubKey, err := x509.MarshalPKIXPublicKey(pubKey)
		if err != nil {
			return nil, err
		}
		hashedBytes := sha256.Sum256(pkixPubKey)
		hint = base64.StdEncoding.EncodeToString(hashedBytes[:])
	} else {
		rawCert = cert[0].Raw
	}

	bundle, err := cbundle.MakeProtobufBundle(hint, rawCert, rekorEntry, timestampBytes)
	if err != nil {
		return nil, err
	}

	var envelope dsse.Envelope
	err = json.Unmarshal(sig, &envelope)
	if err != nil {
		return nil, err
	}

	if len(envelope.Signatures) == 0 {
		return nil, fmt.Errorf("no signature in DSSE envelope")
	}

	sigBytes, err := base64.StdEncoding.DecodeString(envelope.Signatures[0].Sig)
	if err != nil {
		return nil, err
	}

	bundle.Content = &protobundle.Bundle_DsseEnvelope{
		DsseEnvelope: &protodsse.Envelope{
			Payload:     payload,
			PayloadType: envelope.PayloadType,
			Signatures: []*protodsse.Signature{
				{
					Sig: sigBytes,
				},
			},
		},
	}

	contents, err := protojson.Marshal(bundle)
	if err != nil {
		return nil, err
	}

	return contents, nil
}

func validateStatement(payload []byte) (string, error) {
	var statement *intotov1.Statement
	if err := json.Unmarshal(payload, &statement); err != nil {
		return "", fmt.Errorf("invalid statement: %w", err)
	}
	return statement.PredicateType, nil
}
