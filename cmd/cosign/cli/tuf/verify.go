// Copyright 2021 The Sigstore Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tuf

import (
	"context"
	"flag"
	"io/ioutil"
	"path/filepath"

	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/pkg/cosign/tuf"
)

func Verify() *ffcli.Command {
	var (
		flagset = flag.NewFlagSet("cosign tuf verify", flag.ExitOnError)
		root    = flagset.String("root", "", "path to root metadata")
	)

	return &ffcli.Command{
		Name:       "verify",
		ShortUsage: "cosign tuf verify <IMG>",
		ShortHelp:  "verify verifies an image given a known root",
		FlagSet:    flagset,
		Exec: func(ctx context.Context, args []string) error {

			// TODO: Verify multiple images
			return VerifyCmd(ctx, *root, args[0])
		},
	}
}

func VerifyCmd(ctx context.Context, root, image string) error {
	rootPayload, err := ioutil.ReadFile(filepath.Clean(root))
	if err != nil {
		return errors.Wrap(err, "payload from root file")
	}

	return tuf.Verify(rootPayload, image)
}
