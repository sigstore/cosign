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
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/sigstore/cosign/cmd/cosign/cli"
	"github.com/sigstore/cosign/pkg/cosign/tuf"
	"github.com/sigstore/sigstore/pkg/signature"
)

// Init-repo flags:
// --add-<role>-key: path to the public key to add from role
// --<role>-threshold: set a signing threshold for a role (requires root re-signing)
// --root-key: root key reference (private key, kms, sk) used to sign the role metadata

// Path to public key file, URL, KMS URI
type keysFlag []string

func (f *keysFlag) Set(value string) error {
	if _, err := os.Stat(filepath.Clean(value)); os.IsNotExist(err) {
		return err
	}
	*f = append(*f, value)
	return nil
}

func (f *keysFlag) String() string {
	return strings.Join(*f, ",")
}

func InitRepo() *ffcli.Command {
	var (
		flagset          = flag.NewFlagSet("cosign tuf init-repo", flag.ExitOnError)
		rootThreshold    = flagset.Int("root-threshold", 0, "root key threshold")
		addRootKeys      = keysFlag{}
		addTargetsKeys   = keysFlag{}
		addTimestampKeys = keysFlag{}
		signRoot         = keysFlag{}
	)

	// Specify public keys
	flagset.Var(&addRootKeys, "add-root-key", "path to a root public key to add")
	flagset.Var(&addTargetsKeys, "add-targets-key", "path to a targets (and snapshot) public key to add. if not provided, a key will be generated")
	flagset.Var(&addTimestampKeys, "add-timestamp-key", "path to a timestamp public key to add. if not provided, a key will be generated")

	// Specify private keys that may sign metadata (key must be added first)
	flagset.Var(&signRoot, "sign-root", "key reference to a private key used to sign the root metadata")

	return &ffcli.Command{
		Name:       "init-repo",
		ShortUsage: "cosign tuf init-repo <repo>",
		ShortHelp:  "init-repo initializes TUF in a repository",
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
				Thresholds: map[string]int{"root.json": *rootThreshold},
				Signers:    map[string][]signature.Signer{"root.json": signers},
			}
			return InitRepoCmd(ctx, args[0], repoOpts)
		},
	}
}

func getSigners(ctx context.Context, keyRefs []string) ([]signature.Signer, error) {
	var signers []signature.Signer
	for _, key := range keyRefs {
		fmt.Printf("Getting signer for %s... \n", key)
		k, err := cli.SignerFromKeyRef(ctx, key, cli.GetPass)
		if err != nil {
			return nil, err
		}
		signers = append(signers, k)
	}
	return signers, nil
}

func InitRepoCmd(ctx context.Context, repo string, opts tuf.RepoOpts) error {
	// Initialize a new TUF repository with an in-memory store.
	store, err := tuf.NewStore()
	if err != nil {
		return err
	}

	verified, err := tuf.UpdateRepo(ctx, store, opts, false)
	if err != nil {
		return err
	}

	// Maybe upload finalized meta if complete, otherwise write staged JSON.
	if err := tuf.UploadStoreToRegistry(*store, repo, verified); err != nil {
		return err
	}

	// TODO: Print root keys to distribute
	return nil
}
