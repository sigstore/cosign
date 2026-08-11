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

package attest

import (
	"context"
	_ "crypto/sha256" // for `crypto.SHA256`
	"fmt"
	"os"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/signcommon"
	"github.com/sigstore/cosign/v3/internal/ui"
	"github.com/sigstore/cosign/v3/pkg/cosign/attestation"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
)

// nolint
type AttestCommand struct {
	options.KeyOpts
	options.RegistryOptions
	CertPath      string
	CertChainPath string
	NoUpload      bool
	PredicatePath string
	PredicateType string
	Timeout       time.Duration
}

// nolint
func (c *AttestCommand) Exec(ctx context.Context, imageRef string) error {
	// We can't have both a key and a security key
	if options.NOf(c.KeyRef, c.Sk) > 1 {
		return &options.KeyParseError{}
	}

	if c.PredicatePath == "" {
		return fmt.Errorf("predicate cannot be empty")
	}

	predicateURI, err := options.ParsePredicateType(c.PredicateType)
	if err != nil {
		return err
	}
	ref, err := signcommon.ParseOCIReference(ctx, imageRef, c.NameOptions()...)
	if err != nil {
		return fmt.Errorf("parsing reference: %w", err)
	}

	if c.Timeout != 0 {
		var cancelFn context.CancelFunc
		ctx, cancelFn = context.WithTimeout(ctx, c.Timeout)
		defer cancelFn()
	}

	ociremoteOpts, err := c.RegistryOptions.ClientOpts(ctx)
	if err != nil {
		return err
	}
	if c.RegistryOptions.AllowHTTPRegistry || c.RegistryOptions.AllowInsecure {
		ociremoteOpts = append(ociremoteOpts, ociremote.WithNameOptions(name.Insecure))
	}
	digest, err := ociremote.ResolveDigest(ref, ociremoteOpts...)
	if err != nil {
		return err
	}
	h, _ := v1.NewHash(digest.Identifier())
	// Overwrite "ref" with a digest to avoid a race where we use a tag
	// multiple times, and it potentially points to different things at
	// each access.
	ref = digest // nolint

	predicate, err := predicateReader(c.PredicatePath)
	if err != nil {
		return fmt.Errorf("getting predicate reader: %w", err)
	}
	defer predicate.Close()

	sh, err := attestation.GenerateStatement(attestation.GenerateOpts{
		Predicate: predicate,
		Type:      c.PredicateType,
		Digest:    h.Hex,
		Repo:      digest.Repository.String(),
	})
	if err != nil {
		return err
	}

	payload, err := sh.MarshalJSON()
	if err != nil {
		return err
	}

	bundleOpts := signcommon.CommonBundleOpts{
		Payload:       payload,
		Digest:        digest,
		PredicateType: predicateURI,
		BundlePath:    c.BundlePath,
		Upload:        !c.NoUpload,
		OCIRemoteOpts: ociremoteOpts,
	}

	if c.SigningConfig == nil {
		c.SigningConfig = signcommon.NewEmptySigningConfig()
	}

	shouldUpload, err := signcommon.ShouldUploadToTlog(ctx, c.KeyOpts, digest, len(c.SigningConfig.RekorLogURLs()) > 0)
	if err != nil {
		return fmt.Errorf("should upload to tlog: %w", err)
	}

	if !shouldUpload {
		c.SigningConfig.WithRekorLogURLs()
	}

	bundleBytes, err := signcommon.NewAttestationBundle(ctx, c.KeyOpts, c.CertPath, c.CertChainPath, bundleOpts, c.SigningConfig, c.TrustedMaterial)
	if err != nil {
		return fmt.Errorf("creating bundle: %w", err)
	}

	if c.BundlePath != "" {
		if err := os.WriteFile(c.BundlePath, bundleBytes, 0600); err != nil {
			return fmt.Errorf("create bundle file: %w", err)
		}
		ui.Infof(ctx, "Wrote bundle to file %s", c.BundlePath)
	}

	if !c.NoUpload {
		if err := ociremote.WriteAttestationNewBundleFormat(digest, bundleBytes, bundleOpts.PredicateType, ociremoteOpts...); err != nil {
			return fmt.Errorf("writing bundle: %w", err)
		}
	}
	return nil
}
