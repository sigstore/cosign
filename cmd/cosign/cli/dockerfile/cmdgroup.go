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

package dockerfile

import (
	"context"
	"flag"

	"github.com/peterbourgon/ff/v3/ffcli"
)

// Dockerfile subcommand for ffcli.
// Deprecated: this will be deleted when the migration from ffcli to cobra is done.
func Dockerfile() *ffcli.Command {
	var (
		flagset = flag.NewFlagSet("cosign dockerfile", flag.ExitOnError)
	)

	return &ffcli.Command{
		Name:        "dockerfile",
		ShortUsage:  "cosign dockerfile",
		ShortHelp:   "Provides utilities for discovering images in and performing operations on Dockerfiles",
		FlagSet:     flagset,
		Subcommands: []*ffcli.Command{VerifyDockerfile()},
		Exec: func(ctx context.Context, args []string) error {
			return flag.ErrHelp
		},
	}
}
