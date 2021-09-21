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

package cli

import (
	"context"
	"flag"
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/peterbourgon/ff/v3/ffcli"

	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	ociremote "github.com/sigstore/cosign/internal/oci/remote"
	"github.com/sigstore/cosign/pkg/cosign"
)

func Triangulate() *ffcli.Command {
	var (
		flagset = flag.NewFlagSet("cosign triangulate", flag.ExitOnError)
		t       = flagset.String("type", "signature", "related attachment to triangulate (attestation|sbom|signature), default signature")
		regOpts options.RegistryOpts
	)
	options.ApplyRegistryFlags(&regOpts, flagset)
	return &ffcli.Command{
		Name:       "triangulate",
		ShortUsage: "cosign triangulate <image uri>",
		ShortHelp:  "Outputs the located cosign image reference. This is the location cosign stores the specified artifact type.",
		FlagSet:    flagset,
		Exec: func(ctx context.Context, args []string) error {
			if len(args) != 1 {
				return flag.ErrHelp
			}
			return MungeCmd(ctx, regOpts, args[0], *t)
		},
	}
}

func MungeCmd(ctx context.Context, regOpts options.RegistryOpts, imageRef string, attachmentType string) error {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return err
	}

	remoteOpts := regOpts.GetRegistryClientOpts(ctx)
	var dstRef name.Tag
	switch attachmentType {
	case cosign.Signature:
		dstRef, err = ociremote.SignatureTag(ref, ociremote.WithRemoteOptions(remoteOpts...))
	case cosign.SBOM:
		dstRef, err = ociremote.SBOMTag(ref, ociremote.WithRemoteOptions(remoteOpts...))
	case cosign.Attestation:
		dstRef, err = ociremote.AttestationTag(ref, ociremote.WithRemoteOptions(remoteOpts...))
	default:
		err = fmt.Errorf("unknown attachment type %s", attachmentType)
	}
	if err != nil {
		return err
	}

	fmt.Println(dstRef.Name())
	return nil
}
