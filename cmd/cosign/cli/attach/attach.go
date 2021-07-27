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

package attach

import (
	"context"
	"flag"

	"github.com/peterbourgon/ff/v3/ffcli"
)

func Attach() *ffcli.Command {
	var (
		flagset = flag.NewFlagSet("cosign attach", flag.ExitOnError)
	)

	return &ffcli.Command{
		Name:        "attach",
		ShortUsage:  "cosign attach",
		ShortHelp:   "Provides utilities for attaching artifacts to other artifacts in a registry",
		FlagSet:     flagset,
		Subcommands: []*ffcli.Command{Signature(), SBOM()},
		Exec: func(ctx context.Context, args []string) error {
			return flag.ErrHelp
		},
	}
}
