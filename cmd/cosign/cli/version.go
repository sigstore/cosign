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

	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/pkg/errors"

	"github.com/sigstore/cosign/cmd/cosign/cli/options"
)

func Version() *ffcli.Command {
	var (
		flagset = flag.NewFlagSet("cosign version", flag.ExitOnError)
		outJSON = flagset.Bool("json", false, "print JSON instead of text")
	)
	return &ffcli.Command{
		Name:       "version",
		ShortUsage: "cosign version",
		ShortHelp:  "Prints the cosign version",
		FlagSet:    flagset,
		Exec: func(ctx context.Context, args []string) error {
			v := options.VersionInfo()
			res := v.String()
			if *outJSON {
				j, err := v.JSONString()
				if err != nil {
					return errors.Wrap(err, "unable to generate JSON from version info")
				}
				res = j
			}

			fmt.Println(res)
			return nil
		},
	}
}
