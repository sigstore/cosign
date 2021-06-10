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
	"github.com/sigstore/cosign/pkg/cosign/tuf"
	"github.com/sigstore/sigstore/pkg/signature"
)

// Timestamp the metadata. Metadata must otherwise be complete
// cosign tuf timestamp [OPTIONS] <REPO>

// --sign-timestamp: key reference to timestamp key for re-signing

func Timestamp() *ffcli.Command {
	var (
		flagset       = flag.NewFlagSet("cosign tuf timestamp", flag.ExitOnError)
		signTimestamp = keysFlag{}
	)

	// Specify private keys that may sign if initializing from the same device (key must be added first)
	flagset.Var(&signTimestamp, "sign-timestamp", "key reference to a private key used to sign the targets (and snapshot) metadata")

	return &ffcli.Command{
		Name:       "timestamp",
		ShortUsage: "cosign tuf timestamp <repo>",
		ShortHelp:  "timestamp resigns the timestamp",
		FlagSet:    flagset,
		Exec: func(ctx context.Context, args []string) error {
			signers, err := getSigners(ctx, signTimestamp)
			if err != nil {
				return err
			}

			var repoOpts = tuf.RepoOpts{
				Signers: map[string][]signature.Signer{"timestamp.json": signers},
			}
			// TODO: Maybe infer the repo from the targets?
			return UpdateCmd(ctx, args[0], repoOpts)
		},
	}
}
