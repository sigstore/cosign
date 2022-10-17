//
// Copyright 2022 the Sigstore Authors.
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

package verify

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/in-toto/in-toto-golang/in_toto"
	ssldsse "github.com/secure-systems-lab/go-securesystemslib/dsse"

	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/pkcs11key"
	sigs "github.com/sigstore/cosign/pkg/signature"
	"github.com/sigstore/cosign/pkg/types"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
)

// VerifyBlobAttestationCommand verifies an attestation on a supplied blob
// nolint
type VerifyBlobAttestationCommand struct {
	CheckClaims   bool
	KeyRef        string
	PredicateType string

	SignaturePath string // Path to the signature
}

// Exec runs the verification command
func (c *VerifyBlobAttestationCommand) Exec(ctx context.Context, artifactPath string) error {
	if c.SignaturePath == "" {
		return fmt.Errorf("please specify path to the base64 encoded DSSE envelope signature via --signature")
	}

	// TODO: Add support for security keys and keyless signing
	if !options.OneOf(c.KeyRef) {
		return &options.PubKeyParseError{}
	}

	var err error
	co := &cosign.CheckOpts{}

	if c.CheckClaims {
		co.ClaimVerifier = cosign.IntotoSubjectClaimVerifier
	}

	keyRef := c.KeyRef

	// TODO: keyless signing
	co.SigVerifier, err = sigs.PublicKeyFromKeyRef(ctx, keyRef)
	if err != nil {
		return fmt.Errorf("loading public key: %w", err)
	}
	pkcs11Key, ok := co.SigVerifier.(*pkcs11key.Key)
	if ok {
		defer pkcs11Key.Close()
	}

	// Read the signature and decode it (it should be base64-encoded)
	encodedSig, err := os.ReadFile(filepath.Clean(c.SignaturePath))
	if err != nil {
		return fmt.Errorf("reading %s: %w", c.SignaturePath, err)
	}
	decodedSig, err := base64.StdEncoding.DecodeString(string(encodedSig))
	if err != nil {
		return fmt.Errorf("decoding signature: %w", err)
	}

	// Verify the signature on the attestation against the provided public key
	env := ssldsse.Envelope{}
	if err := json.Unmarshal(decodedSig, &env); err != nil {
		return fmt.Errorf("marshaling envelope: %w", err)
	}

	if env.PayloadType != types.IntotoPayloadType {
		return cosign.NewVerificationError("invalid payloadType %s on envelope. Expected %s", env.PayloadType, types.IntotoPayloadType)
	}
	dssev, err := ssldsse.NewEnvelopeVerifier(&dsse.VerifierAdapter{SignatureVerifier: co.SigVerifier})
	if err != nil {
		return fmt.Errorf("new envelope verifier: %w", err)
	}
	if _, err := dssev.Verify(&env); err != nil {
		return fmt.Errorf("dsse verify: %w", err)
	}

	// Verify the attestation is for the provided blob and the predicate type
	if err := verifyBlobAttestation(env, artifactPath, c.PredicateType); err != nil {
		return err
	}

	fmt.Fprintln(os.Stderr, "Verified OK")
	return nil
}

func verifyBlobAttestation(env ssldsse.Envelope, blobPath, predicateType string) error {
	artifact, err := os.ReadFile(blobPath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", blobPath, err)
	}

	// Get the actual digest of the blob
	digest, _, err := signature.ComputeDigestForSigning(bytes.NewReader(artifact), crypto.SHA256, []crypto.Hash{crypto.SHA256, crypto.SHA384})
	if err != nil {
		return err
	}
	actualDigest := strings.ToLower(hex.EncodeToString(digest))

	// Get the expected digest from the attestation
	decodedPredicate, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return fmt.Errorf("decoding dsse payload: %w", err)
	}
	var statement in_toto.Statement
	if err := json.Unmarshal(decodedPredicate, &statement); err != nil {
		return fmt.Errorf("decoding predicate: %w", err)
	}

	// Compare the actual and expected
	if statement.Subject == nil {
		return fmt.Errorf("no subject in intoto statement")
	}

	for _, subj := range statement.Subject {
		if err := verifySubject(statement, subj, blobPath, actualDigest, predicateType); err == nil {
			return nil
		}
	}
	return fmt.Errorf("attestation does not contain a subject matching the provided blob")
}

func verifySubject(statement in_toto.Statement, subject in_toto.Subject, blobPath, actualDigest, predicateType string) error {
	sha256Digest, ok := subject.Digest["sha256"]
	if !ok {
		return fmt.Errorf("no sha256 digest available")
	}

	if sha256Digest != actualDigest {
		return fmt.Errorf("expected digest %s but %s has a digest of %s", sha256Digest, blobPath, actualDigest)
	}

	// Check the predicate
	parsedPredicateType, err := options.ParsePredicateType(predicateType)
	if err != nil {
		return fmt.Errorf("parsing predicate type %s: %w", predicateType, err)
	}
	if statement.PredicateType != parsedPredicateType {
		return fmt.Errorf("expected predicate type %s but is %s: specify an expected predicate type with the --type flag", parsedPredicateType, statement.PredicateType)
	}
	return nil
}
