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

// Update can add/remove role keys. Prompting for publishing if the threshold is met.
// Roots are always versioned: a staged.root.json will be moved to <version>.root.json
// Other metadata will move from staged.<role>.json to role.json (e.g. updating a target)
//
//
// Update flags:
// [all init flags]
// --remove-<role>-key: path to the public key to remove from role

// Updates will require additional signing, you can specify the keys

func Update() *ffcli.Command {
	var (
		flagset       = flag.NewFlagSet("cosign tuf update", flag.ExitOnError)
		rootThreshold = flagset.Int("root-threshold", 0, "root key threshold")

		addRootKeys         = keysFlag{}
		addTargetsKeys      = keysFlag{}
		addTimestampKeys    = keysFlag{}
		removeRootKeys      = keysFlag{}
		removeTargetsKeys   = keysFlag{}
		removeTimestampKeys = keysFlag{}
		signRoot            = keysFlag{}
	)

	// Specify adding public keys in case of asynchronous signing
	flagset.Var(&addRootKeys, "add-root-key", "path to a root public key to add")
	flagset.Var(&addTargetsKeys, "add-targets-key", "path to a targets (and snapshot) public key to add. if not provided, a key will be generated")
	flagset.Var(&addTimestampKeys, "add-timestamp-key", "path to a timestamp public key to add. if not provided, a key will be generated")

	// Specify removing public keys
	flagset.Var(&removeRootKeys, "remove-root-key", "path to a root public key to add")
	flagset.Var(&removeTargetsKeys, "remove-targets-key", "path to a targets (and snapshot) public key to add. if not provided, a key will be generated")
	flagset.Var(&removeTimestampKeys, "remove-timestamp-key", "path to a timestamp public key to add. if not provided, a key will be generated")

	// Specify private keys that may sign root metadata if initializing from the same device (key must be added first)
	flagset.Var(&signRoot, "sign-root", "key reference to a private key used to sign the root metadata")

	return &ffcli.Command{
		Name:       "update",
		ShortUsage: "cosign tuf update <repo>",
		ShortHelp:  "update initializes TUF in a repository",
		FlagSet:    flagset,
		Exec: func(ctx context.Context, args []string) error {
			signers, err := getSigners(ctx, signRoot)
			if err != nil {
				return err
			}

			var repoOpts = tuf.RepoOpts{
				Keys: map[string][]string{
					"root.json":      addRootKeys,
					"targets.json":   addTargetsKeys,
					"snapshot.json":  addTargetsKeys,
					"timestamp.json": addTimestampKeys},
				RemoveKeys: map[string][]string{
					"root.json":      removeRootKeys,
					"targets.json":   removeTargetsKeys,
					"snapshot.json":  removeTargetsKeys,
					"timestamp.json": removeTimestampKeys},
				Thresholds: map[string]int{"root.json": *rootThreshold},
				Signers:    map[string][]signature.Signer{"root.json": signers},
			}
			return UpdateCmd(ctx, args[0], repoOpts)
		},
	}
}

func UpdateCmd(ctx context.Context, repo string, opts tuf.RepoOpts) error {
	// Get an in-memory store from the registry
	store, staged, err := tuf.GetStoreFromRegistry(repo)
	if err != nil {
		return err
	}

	verified, err := tuf.UpdateRepo(ctx, &store, opts, staged)
	if err != nil {
		return err
	}

	// Maybe upload finalized meta if complete, otherwise write staged JSON.
	if err := tuf.UploadStoreToRegistry(store, repo, verified); err != nil {
		return err
	}

	return nil
}
