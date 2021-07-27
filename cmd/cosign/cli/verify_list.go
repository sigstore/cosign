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
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/peterbourgon/ff/v3/ffcli"
	"strings"
)

// VerifyListCommand verifies all signatures on a supplied container image
type VerifyListCommand struct {
	VerifyCommand
}

// VerifyList builds and returns an ffcli command
func VerifyList() *ffcli.Command {
	cmd := VerifyListCommand{VerifyCommand: VerifyCommand{}}
	flagset := flag.NewFlagSet("cosign verify-list", flag.ExitOnError)
	applyVerifyFlags(&cmd.VerifyCommand, flagset)

	return &ffcli.Command{
		Name:       "verify-list",
		ShortUsage: "cosign verify-list -key <key path>|<key url>|<kms uri> <path/to/Dockerfile>",
		ShortHelp:  "Verify all signatures on the specified image",
		LongHelp: `Verify all signatures and annotations on the image by recursively checking claims
against the transparency log.

EXAMPLES
  # verify all cosign claims and signing certificates on the image
  cosign verify-list <IMAGE>
  `,

		FlagSet: flagset,
		Exec:    cmd.Exec,
	}
}

// Exec runs the verification command
func (c *VerifyListCommand) Exec(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return flag.ErrHelp
	}

	for _, imageRef := range args {
		images, err := c.getAllTagsForImageRef(ctx, imageRef)
		if err != nil {
			return err
		}

		println("Images to be verified:")
		for _, image := range images {
			println("* ", image)
		}

		err = c.VerifyCommand.Exec(ctx, images)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *VerifyListCommand) getAllTagsForImageRef(ctx context.Context, imageRef string) ([]string, error) {
	srcRef, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, err
	}

	srcSigRepo, err := TargetRepositoryForImage(srcRef)
	if err != nil {
		return nil, err
	}

	regClientOpts := DefaultRegistryClientOpts(ctx)

	list, err := remote.List(srcSigRepo, regClientOpts...)
	if err != nil {
		return nil, err
	}

	result := make([]string, 0, len(list))
	for _, tag := range list {
		if strings.HasSuffix(tag, ".sig") {
			continue
		}
		result = append(result, fmt.Sprintf("%s:%s", imageRef, tag))
	}

	return result, nil
}
