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
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/sigstore/cosign/v2/cmd/cosign/cli"
	"github.com/sigstore/cosign/v2/internal/ui"

	// Register the provider-specific plugins
	_ "github.com/sigstore/sigstore/pkg/signature/kms/aws"
	_ "github.com/sigstore/sigstore/pkg/signature/kms/azure"
	_ "github.com/sigstore/sigstore/pkg/signature/kms/gcp"
	_ "github.com/sigstore/sigstore/pkg/signature/kms/hashivault"
)

func main() {
	// Fix up flags to POSIX standard flags.
	ctx := context.Background()
	for i, arg := range os.Args {
		if (strings.HasPrefix(arg, "-") && len(arg) == 2) || (strings.HasPrefix(arg, "--") && len(arg) >= 4) {
			continue
		}
		if strings.HasPrefix(arg, "--") && len(arg) == 3 {
			// Handle --o, convert to -o
			newArg := fmt.Sprintf("-%c", arg[2])
			ui.Warn(ctx, "the flag %s is deprecated and will be removed in a future release. Please use the flag %s.", arg, newArg)
			os.Args[i] = newArg
		} else if strings.HasPrefix(arg, "-") && len(arg) > 1 {
			// Handle -output, convert to --output
			newArg := fmt.Sprintf("-%s", arg)
			newArgType := "flag"
			if newArg == "--version" {
				newArg = "version"
				newArgType = "subcommand"
			}
			ui.Warn(ctx, "the %s flag is deprecated and will be removed in a future release. "+
				"Please use the %s %s instead.",
				arg, newArg, newArgType,
			)
			os.Args[i] = newArg
		}
	}

	if err := cli.New().Execute(); err != nil {
		log.Fatalf("error during command execution: %v", err)
	}
}
