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
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/sigstore/cosign/pkg/cosign/tuf"
	"github.com/sigstore/sigstore/pkg/signature"
)

// Sign and snapshot new targets.
// cosign tuf sign-and-snapshot [OPTIONS] <REPO>

// --remove: Removes the specified image(s) from targets (TODO)
// --target: Specify a target image
// --sign-targets: key reference to target key for re-signing

type targetsFlag []string

func (f *targetsFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}

func (f *targetsFlag) String() string {
	return strings.Join(*f, ",")
}

func SignAndSnapshot() *ffcli.Command {
	var (
		flagset     = flag.NewFlagSet("cosign tuf sign-and-snapshot", flag.ExitOnError)
		signTargets = keysFlag{}
		targets     = targetsFlag{}
	)

	// Specify private keys that may sign if initializing from the same device (key must be added first)
	flagset.Var(&signTargets, "sign-targets", "key reference to a private key used to sign the targets (and snapshot) metadata")
	flagset.Var(&targets, "target", "reference to container image to sign and snapshot")

	return &ffcli.Command{
		Name:       "sign-and-snapshot",
		ShortUsage: "cosign tuf sign-and-snapshot <repo>",
		ShortHelp:  "sign-and-snapshot configures and snapshots new targets",
		FlagSet:    flagset,
		Exec: func(ctx context.Context, args []string) error {
			signers, err := getSigners(ctx, signTargets)
			if err != nil {
				return err
			}

			var repoOpts = tuf.RepoOpts{
				Signers: map[string][]signature.Signer{"targets.json": signers, "snapshot.json": signers},
				Targets: targets,
			}
			// TODO: Maybe infer the repo from the targets?
			return UpdateCmd(ctx, args[0], repoOpts)
		},
	}
}
