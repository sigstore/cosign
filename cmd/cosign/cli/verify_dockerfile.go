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
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/pkg/errors"
)

// VerifyCommand verifies a signature on a supplied container image
type VerifyDockerfileCommand struct {
	VerifyCommand
	BaseOnly bool
}

// Verify builds and returns an ffcli command
func VerifyDockerfile() *ffcli.Command {
	cmd := VerifyDockerfileCommand{VerifyCommand: VerifyCommand{}}
	flagset := flag.NewFlagSet("cosign verify-dockerfile", flag.ExitOnError)
	flagset.BoolVar(&cmd.BaseOnly, "base-image-only", false, "only verify the base image (the last FROM image in the Dockerfile)")
	applyVerifyFlags(&cmd.VerifyCommand, flagset)

	return &ffcli.Command{
		Name:       "verify-dockerfile",
		ShortUsage: "cosign verify-dockerfile -key <key path>|<key url>|<kms uri> <path/to/Dockerfile>",
		ShortHelp:  "Verify a signature on the base image specified in the Dockerfile",
		LongHelp: `Verify signature and annotations on images in a Dockerfile by checking claims
against the transparency log.

Shell-like variables in the Dockerfile's FROM lines will be substituted with values from the OS ENV.

EXAMPLES
  # verify cosign claims and signing certificates on the FROM images in the Dockerfile
  cosign verify-dockerfile <path/to/Dockerfile>

  # only verify the base image (the last FROM image)
  cosign verify-dockerfile -base-image-only <path/to/Dockerfile>

  # additionally verify specified annotations
  cosign verify-dockerfile -a key1=val1 -a key2=val2 <path/to/Dockerfile>

  # (experimental) additionally, verify with the transparency log
  COSIGN_EXPERIMENTAL=1 cosign verify-dockerfile <path/to/Dockerfile>

  # verify images with public key
  cosign verify-dockerfile -key cosign.pub <path/to/Dockerfile>

  # verify images with public key provided by URL
  cosign verify-dockerfile -key https://host.for/<FILE> <path/to/Dockerfile>

  # verify images with public key stored in Azure Key Vault
  cosign verify-dockerfile -key azurekms://[VAULT_NAME][VAULT_URI]/[KEY] <path/to/Dockerfile>

  # verify images with public key stored in AWS KMS
  cosign verify-dockerfile -key awskms://[ENDPOINT]/[ID/ALIAS/ARN] <path/to/Dockerfile>

  # verify images with public key stored in Google Cloud KMS
  cosign verify-dockerfile -key gcpkms://projects/[PROJECT]/locations/global/keyRings/[KEYRING]/cryptoKeys/[KEY] <path/to/Dockerfile>

  # verify images with public key stored in Hashicorp Vault
  cosign verify-dockerfile -key hashivault://[KEY] <path/to/Dockerfile>`,

		FlagSet: flagset,
		Exec:    cmd.Exec,
	}
}

// Exec runs the verification command
func (c *VerifyDockerfileCommand) Exec(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return flag.ErrHelp
	}

	dockerfile, err := os.Open(args[0])
	if err != nil {
		return fmt.Errorf("could not open Dockerfile: %v", err)
	}
	defer dockerfile.Close()

	images, err := getImagesFromDockerfile(dockerfile)
	if err != nil {
		return fmt.Errorf("failed extracting images from Dockerfile: %v", err)
	}
	if len(images) == 0 {
		return errors.New("no images found in Dockerfile")
	}
	if c.BaseOnly {
		images = images[len(images)-1:]
	}
	fmt.Fprintf(os.Stderr, "Extracted image(s): %s\n", strings.Join(images, ", "))

	return c.VerifyCommand.Exec(ctx, images)
}

func getImagesFromDockerfile(dockerfile io.Reader) ([]string, error) {
	var images []string
	fileScanner := bufio.NewScanner(dockerfile)
	for fileScanner.Scan() {
		line := strings.TrimSpace(fileScanner.Text())
		fileScanner.Scan()
		nextLine := strings.TrimSpace(fileScanner.Text())
		if strings.HasPrefix(line, "FROM") {
			images = append(images, getImageFromLine(line))
		} else if strings.HasPrefix(line, "ARG") && strings.HasPrefix(nextLine, "FROM") {
			images = append(images, getImageFromLine(line))
		}
	}
	if err := fileScanner.Err(); err != nil {
		return nil, err
	}
	return images, nil
}

func getImageFromLine(line string) string {
	line = strings.TrimPrefix(line, "FROM") // Remove "FROM" prefix
	line = os.ExpandEnv(line)               // Substitute templated vars
	fields := strings.Fields(line)
	for i := len(fields) - 1; i > 0; i-- {
		if strings.Contains(fields[i], "=") {
			fields = strings.SplitN(fields[i], "=", 2)
			break
		}
		// Remove the "AS" portion of line
		if strings.EqualFold(fields[i], "AS") {
			fields = fields[:i]
			break
		}
	}
	return fields[len(fields)-1] // The image should be the last portion of the line that remains
}
