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

	"github.com/peterbourgon/ff/v3/ffcli"
)

func Tuf() *ffcli.Command {
	var (
		flagset = flag.NewFlagSet("cosign tuf", flag.ExitOnError)
		// force   = flagset.Bool("f", false, "skip warnings and confirmations")
	)

	return &ffcli.Command{
		Name:        "tuf",
		ShortUsage:  "cosign tuf",
		ShortHelp:   "tuf contains commands to manage a TUF repository",
		FlagSet:     flagset,
		Subcommands: []*ffcli.Command{InitRepo(), Update(), SignAndSnapshot(), Timestamp(), Verify()},
		Exec: func(ctx context.Context, args []string) error {
			return flag.ErrHelp
		},
	}
}
