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

package verify

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/internal/ui"
	"github.com/sigstore/cosign/v3/pkg/blob"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	sgverify "github.com/sigstore/sigstore-go/pkg/verify"
)

// nolint
type VerifyBlobCmd struct {
	options.KeyOpts
	options.CertVerifyOptions
	TrustedRootPath              string
	CertGithubWorkflowTrigger    string
	CertGithubWorkflowSHA        string
	CertGithubWorkflowName       string
	CertGithubWorkflowRepository string
	CertGithubWorkflowRef        string
	IgnoreSCT                    bool
	Offline                      bool
	UseSignedTimestamps          bool
	IgnoreTlog                   bool
}

// nolint
func (c *VerifyBlobCmd) Exec(ctx context.Context, blobRef string) error {
	// key and cert identity are mutually exclusive
	if options.NOf(c.KeyRef, c.CertIdentity, c.CertIdentityRegexp) > 1 {
		return &options.KeyAndIdentityParseError{}
	}

	// Key and sk are mutually exclusive.
	if options.NOf(c.KeyRef, c.Sk) > 1 {
		return &options.PubKeyParseError{}
	}

	if c.BundlePath == "" {
		return fmt.Errorf("please specify --bundle")
	}

	var identities []cosign.Identity
	var err error
	if c.KeyRef == "" && !c.Sk {
		identities, err = c.Identities()
		if err != nil {
			return err
		}
	}

	co := &cosign.CheckOpts{
		CertGithubWorkflowTrigger:    c.CertGithubWorkflowTrigger,
		CertGithubWorkflowSha:        c.CertGithubWorkflowSHA,
		CertGithubWorkflowName:       c.CertGithubWorkflowName,
		CertGithubWorkflowRepository: c.CertGithubWorkflowRepository,
		CertGithubWorkflowRef:        c.CertGithubWorkflowRef,
		IgnoreSCT:                    c.IgnoreSCT,
		Identities:                   identities,
		Offline:                      c.Offline,
		IgnoreTlog:                   c.IgnoreTlog,
		UseSignedTimestamps:          c.UseSignedTimestamps,
	}
	vOfflineKey := verifyOfflineWithKey(c.KeyRef, c.Sk, co)

	// User provides a key. Otherwise, verification requires a Fulcio certificate
	// provided in an attached bundle.
	var closeSV func()
	co.SigVerifier, closeSV, err = LoadVerifierFromKey(ctx, c.KeyRef, c.Slot, c.Sk)
	if err != nil {
		return fmt.Errorf("loading verifier from key opts: %w", err)
	}
	defer closeSV()

	err = SetTrustedMaterial(c.TrustedRootPath, vOfflineKey, co)
	if err != nil {
		return fmt.Errorf("setting trusted material: %w", err)
	}

	bundle, err := sgbundle.LoadJSONFromPath(c.BundlePath)
	if err != nil {
		return err
	}

	var artifactPolicyOption sgverify.ArtifactPolicyOption
	blobBytes, err := payloadBytes(blobRef)
	if err != nil {
		alg, digest, payloadDigestError := payloadDigest(blobRef)
		if payloadDigestError != nil {
			return err
		}
		artifactPolicyOption = sgverify.WithArtifactDigest(alg, digest)
	} else {
		artifactPolicyOption = sgverify.WithArtifact(bytes.NewReader(blobBytes))
	}

	_, err = cosign.VerifyNewBundle(ctx, co, artifactPolicyOption, bundle)
	if err != nil {
		return err
	}

	ui.Infof(ctx, "Verified OK")
	return nil
}

func payloadBytes(blobRef string) ([]byte, error) {
	var blobBytes []byte
	var err error
	if blobRef == "-" {
		blobBytes, err = io.ReadAll(os.Stdin)
	} else {
		blobBytes, err = blob.LoadFileOrURL(blobRef)
	}
	if err != nil {
		return nil, err
	}
	return blobBytes, nil
}

func payloadDigest(blobRef string) (string, []byte, error) {
	hexAlg, hexDigest, ok := strings.Cut(blobRef, ":")
	if !ok {
		return "", nil, fmt.Errorf("invalid digest format")
	}
	digestBytes, err := hex.DecodeString(hexDigest)
	if err != nil {
		return "", nil, err
	}
	return hexAlg, digestBytes, nil
}
