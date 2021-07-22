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

package main

import (
	"fmt"
	"log"
	"os"
	"runtime/debug"
	"strings"

	"github.com/sigstore/cosign/cmd/cosign/cli"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
)

func main() {
	// Fix up flags to POSIX standard flags.
	for i, arg := range os.Args {
		if (strings.HasPrefix(arg, "-") && len(arg) == 2) || (strings.HasPrefix(arg, "--") && len(arg) >= 4) {
			continue
		}
		if strings.HasPrefix(arg, "--") && len(arg) == 3 {
			// Handle --o, convert to -o
			newArg := fmt.Sprintf("-%c", arg[2])
			fmt.Fprintf(os.Stderr, "WARNING: the flag %s is deprecated and will be removed in a future release. Please use the flag %s.\n", arg, newArg)
			os.Args[i] = newArg
		} else if strings.HasPrefix(arg, "-") {
			// Handle -output, convert to --output
			newArg := fmt.Sprintf("-%s", arg)
			fmt.Fprintf(os.Stderr, "WARNING: the flag %s is deprecated and will be removed in a future release. Please use the flag %s.\n", arg, newArg)
			os.Args[i] = newArg
		}
	}

	// Extra migration hacks, while we still use ffcli, we will add a -- to
	// escape the remaining args to let them be passed to cobra.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "public-key", "policy-init", "generate-key-pair",
			"generate", "sign", "sign-blob",
			"attest", "copy", "clean",
			"version":
			// cobra.
		default:
			// ffcli
			os.Args = append([]string{os.Args[0], "--"}, os.Args[1:]...)
		}
	}

	if err := cli.New().Execute(); err != nil {
		log.Fatalf("error during command execution: %v", err)
	}
}

func init() {
	// look for the default version and replace it, if found, from runtime build info
	if options.GitVersion != "devel" {
		return
	}

	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}

	// Version is set in artifacts built with -X github.com/sigstore/cosign/cli.GitVersion=1.2.3
	// Ensure version is also set when installed via go install github.com/sigstore/cosign/cmd/cosign
	options.GitVersion = bi.Main.Version
}
