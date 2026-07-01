//
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

package verify

import (
	"context"
	"crypto"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	internal "github.com/sigstore/cosign/v3/internal/pkg/cosign"
	payloadsize "github.com/sigstore/cosign/v3/internal/pkg/cosign/payload/size"
	"github.com/sigstore/cosign/v3/internal/ui"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/oci/static"
	"github.com/sigstore/cosign/v3/pkg/policy"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	sgverify "github.com/sigstore/sigstore-go/pkg/verify"
)

// VerifyBlobAttestationCommand verifies an attestation on a supplied blob
// nolint
type VerifyBlobAttestationCommand struct {
	options.KeyOpts
	options.CertVerifyOptions

	TrustedRootPath string

	CertGithubWorkflowTrigger    string
	CertGithubWorkflowSHA        string
	CertGithubWorkflowName       string
	CertGithubWorkflowRepository string
	CertGithubWorkflowRef        string

	IgnoreSCT  bool
	Offline    bool
	IgnoreTlog bool

	CheckClaims   bool
	PredicateType string
	// TODO: Add policies

	UseSignedTimestamps bool

	Digest        string
	DigestAlg     string
	HashAlgorithm crypto.Hash
}

// Exec runs the verification command
func (c *VerifyBlobAttestationCommand) Exec(ctx context.Context, artifactPath string) (err error) {
	if c.BundlePath == "" {
		return fmt.Errorf("please specify --bundle")
	}

	// always default to sha256 if the algorithm hasn't been explicitly set
	if c.HashAlgorithm == 0 {
		c.HashAlgorithm = crypto.SHA256
	}

	// Require a key OR a local bundle file that has the cert.
	if options.NOf(c.KeyRef, c.Sk, c.BundlePath) == 0 {
		return fmt.Errorf("provide a key with --key or --sk, or a bundle with --bundle")
	}

	// key and cert identity are mutually exclusive
	if options.NOf(c.KeyRef, c.CertIdentity, c.CertIdentityRegexp) > 1 {
		return &options.KeyAndIdentityParseError{}
	}

	// We can't have both a key and a security key
	if options.NOf(c.KeyRef, c.Sk) > 1 {
		return &options.KeyParseError{}
	}

	var identities []cosign.Identity
	if c.KeyRef == "" {
		identities, err = c.Identities()
		if err != nil {
			return err
		}
	}

	co := &cosign.CheckOpts{
		Identities:                   identities,
		CertGithubWorkflowTrigger:    c.CertGithubWorkflowTrigger,
		CertGithubWorkflowSha:        c.CertGithubWorkflowSHA,
		CertGithubWorkflowName:       c.CertGithubWorkflowName,
		CertGithubWorkflowRepository: c.CertGithubWorkflowRepository,
		CertGithubWorkflowRef:        c.CertGithubWorkflowRef,
		IgnoreSCT:                    c.IgnoreSCT,
		Offline:                      c.Offline,
		IgnoreTlog:                   c.IgnoreTlog,
		UseSignedTimestamps:          c.UseSignedTimestamps,
	}
	vOfflineKey := verifyOfflineWithKey(c.KeyRef, c.Sk, co)

	// User provides a key. Otherwise, verification requires a Fulcio certificate
	// provided in an attached bundle.
	var closeSV func()
	co.SigVerifier, closeSV, err = LoadVerifierFromKey(ctx, c.KeyRef, c.Slot, c.HashAlgorithm, c.Sk)
	if err != nil {
		return fmt.Errorf("loading verifier from key opts: %w", err)
	}
	defer closeSV()

	var h v1.Hash
	var digest []byte
	if c.CheckClaims {
		if artifactPath != "" {
			if c.Digest != "" {
				ui.Warnf(ctx, "Ignoring provided --digest in favor of provided blob")
			}
			// For the legacy (non-bundle) verification path we still need to
			// compute the digest manually.  Pick the hash algorithm to use:
			// default to SHA-256 for backward compatibility; honor --digestAlg
			// so attestations produced against e.g. SHA-512 can be verified.
			hashName := "sha256"
			hashAlg := crypto.SHA256
			if c.DigestAlg != "" {
				parsed, err := parseBlobHashAlgorithm(c.DigestAlg)
				if err != nil {
					return err
				}
				hashName = c.DigestAlg
				hashAlg = parsed
			}

			f, err := os.Open(filepath.Clean(artifactPath))
			if err != nil {
				return err
			}
			defer f.Close()
			fileInfo, err := f.Stat()
			if err != nil {
				return err
			}
			err = payloadsize.CheckSize(uint64(fileInfo.Size()))
			if err != nil {
				return err
			}

			payload := internal.NewHashReader(f, hashAlg)
			if _, err := io.ReadAll(&payload); err != nil {
				return err
			}
			digest = payload.Sum(nil)
			h = v1.Hash{
				Hex:       hex.EncodeToString(digest),
				Algorithm: hashName,
			}
		} else if c.Digest != "" && c.DigestAlg != "" {
			digest, err = hex.DecodeString(c.Digest)
			if err != nil {
				return fmt.Errorf("unable to decode provided digest: %w", err)
			}
			h = v1.Hash{
				Hex:       c.Digest,
				Algorithm: c.DigestAlg,
			}
		}
		co.ClaimVerifier = cosign.IntotoSubjectClaimVerifier
	}

	err = SetTrustedMaterial(c.TrustedRootPath, vOfflineKey, co)
	if err != nil {
		return fmt.Errorf("setting trusted material: %w", err)
	}

	bundle, err := sgbundle.LoadJSONFromPath(c.BundlePath)
	if err != nil {
		return err
	}

	var policyOpt sgverify.ArtifactPolicyOption
	switch {
	case !c.CheckClaims:
		policyOpt = sgverify.WithoutArtifactUnsafe()
	case artifactPath != "":
		// Pass the artifact directly so sigstore-go can peek at the bundle
		// and choose the correct hash algorithm automatically, rather than
		// requiring the caller to supply --digestAlg up-front.
		artifactFile, err := os.Open(filepath.Clean(artifactPath))
		if err != nil {
			return err
		}
		defer artifactFile.Close()
		policyOpt = sgverify.WithArtifact(artifactFile)
	default:
		policyOpt = sgverify.WithArtifactDigest(h.Algorithm, digest)
	}

	_, err = cosign.VerifyNewBundle(ctx, co, policyOpt, bundle)
	if err != nil {
		return err
	}

	sigContent, err := bundle.SignatureContent()
	if err != nil {
		return fmt.Errorf("fetching signature content: %w", err)
	}

	envContent := sigContent.EnvelopeContent()
	if envContent == nil {
		return fmt.Errorf("bundle does not contain a DSSE envelope")
	}

	rawEnv := envContent.RawEnvelope()
	if rawEnv == nil {
		return fmt.Errorf("bundle does not contain a raw DSSE envelope")
	}

	payloadBytes, err := json.Marshal(rawEnv)
	if err != nil {
		return fmt.Errorf("marshaling envelope: %w", err)
	}

	att, err := static.NewAttestation(payloadBytes)
	if err != nil {
		return fmt.Errorf("creating attestation from envelope: %w", err)
	}

	// This checks the predicate type -- if no error is returned and no payload is, then
	// the attestation is not of the given predicate type.
	b, gotPredicateType, err := policy.AttestationToPayloadJSON(ctx, c.PredicateType, att)
	if err != nil {
		return fmt.Errorf("converting to consumable policy validation: %w", err)
	}
	if b == nil {
		return fmt.Errorf("invalid predicate type, expected %s got %s", c.PredicateType, gotPredicateType)
	}

	ui.Infof(ctx, "Verified OK")
	return nil
}

// parseBlobHashAlgorithm maps the --digestAlg name used by
// verify-blob-attestation to a crypto.Hash. Only algorithms actually
// supported as in-toto subject digest algorithms are accepted.
func parseBlobHashAlgorithm(name string) (crypto.Hash, error) {
	switch name {
	case "sha256":
		return crypto.SHA256, nil
	case "sha384":
		return crypto.SHA384, nil
	case "sha512":
		return crypto.SHA512, nil
	}
	return 0, fmt.Errorf("unsupported --digestAlg %q; supported values are sha256, sha384, sha512", name)
}
