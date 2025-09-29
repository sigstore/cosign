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

package triangulate

import (
	"context"
	"fmt"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
)

func MungeCmd(ctx context.Context, regOpts options.RegistryOptions, imageRef string, attachmentType string) error {
	ref, err := name.ParseReference(imageRef, regOpts.NameOptions()...)
	if err != nil {
		return err
	}

	ociremoteOpts, err := regOpts.ClientOpts(ctx)
	if err != nil {
		return fmt.Errorf("constructing client options: %w", err)
	}

	var dstRef name.Tag
	var dstRefName string

	switch attachmentType {
	case cosign.Signature:
		dstRef, err = ociremote.SignatureTag(ref, ociremoteOpts...)
		dstRefName = dstRef.Name()
	case cosign.SBOM:
		fmt.Fprintln(os.Stderr, options.SBOMAttachmentDeprecation)
		dstRef, err = ociremote.SBOMTag(ref, ociremoteOpts...)
		dstRefName = dstRef.Name()
	case cosign.Attestation:
		dstRef, err = ociremote.AttestationTag(ref, ociremoteOpts...)
		dstRefName = dstRef.Name()
	case cosign.Digest:
		dstRef, err = ociremote.DigestTag(ref, ociremoteOpts...)
		dstRefName = fmt.Sprint(dstRef.Repository.Name(), "@", dstRef.TagStr())
	default:
		err = fmt.Errorf("unknown attachment type %s", attachmentType)
	}
	if err != nil {
		return err
	}

	fmt.Println(dstRefName)
	return nil
}
