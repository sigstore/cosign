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
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/pkg/errors"
)

// VerifyCommand verifies all image signatures on a supplied k8s resource
type VerifyManifestCommand struct {
	VerifyCommand
}

// Verify builds and returns an ffcli command
func VerifyManifest() *ffcli.Command {
	cmd := VerifyManifestCommand{VerifyCommand: VerifyCommand{}}
	flagset := flag.NewFlagSet("cosign verify-manifest", flag.ExitOnError)
	applyVerifyFlags(&cmd.VerifyCommand, flagset)

	return &ffcli.Command{
		Name:       "verify-manifest",
		ShortUsage: "cosign verify-manifest -key <key path>|<key url>|<kms uri> <path/to/manifest>",
		ShortHelp:  "Verify all signatures of images specified in the manifest",
		LongHelp: `Verify all signature of images in a Kubernetes resource manifest by checking claims
against the transparency log.

EXAMPLES
  # verify cosign claims and signing certificates on images in the manifest
  cosign verify-manifest <path/to/my-deployment.yaml>

  # additionally verify specified annotations
  cosign verify-manifest -a key1=val1 -a key2=val2 <path/to/my-deployment.yaml>

  # (experimental) additionally, verify with the transparency log
  COSIGN_EXPERIMENTAL=1 cosign verify-manifest <path/to/my-deployment.yaml>

  # verify images with public key
  cosign verify-manifest -key cosign.pub <path/to/my-deployment.yaml>

  # verify images with public key provided by URL
  cosign verify-manifest -key https://host.for/<FILE> <path/to/my-deployment.yaml>

  # verify images with public key stored in Azure Key Vault
  cosign verify-manifest -key azurekms://[VAULT_NAME][VAULT_URI]/[KEY] <path/to/my-deployment.yaml>

  # verify images with public key stored in AWS KMS
  cosign verify-manifest -key awskms://[ENDPOINT]/[ID/ALIAS/ARN] <path/to/my-deployment.yaml>

  # verify images with public key stored in Google Cloud KMS
  cosign verify-manifest -key gcpkms://projects/[PROJECT]/locations/global/keyRings/[KEYRING]/cryptoKeys/[KEY] <path/to/my-deployment.yaml>

  # verify images with public key stored in Hashicorp Vault
  cosign verify-manifest -key hashivault://[KEY] <path/to/my-deployment.yaml>`,

		FlagSet: flagset,
		Exec:    cmd.Exec,
	}
}

// Exec runs the verification command
func (c *VerifyManifestCommand) Exec(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return flag.ErrHelp
	}

	manifestPath := args[0]

	err := isExtensionAllowed(manifestPath)
	if err != nil {
		return errors.Wrap(err, "check if extension is valid")
	}

	manifest, err := ioutil.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("could not read manifest: %v", err)
	}

	images, err := getImagesFromYamlManifest(string(manifest))
	if err != nil {
		return fmt.Errorf("failed extracting images from manifest: %v", err)
	}
	if len(images) == 0 {
		return errors.New("no images found in manifest")
	}
	fmt.Fprintf(os.Stderr, "Extracted image(s): %s\n", strings.Join(images, ", "))

	return c.VerifyCommand.Exec(ctx, images)
}

func getImagesFromYamlManifest(manifest string) ([]string, error) {
	var images []string
	re := regexp.MustCompile(`image:\s?(?P<Image>.*)\s?`)
	for _, s := range re.FindAllStringSubmatch(manifest, -1) {
		images = append(images, s[1])
	}
	return images, nil
}

func isExtensionAllowed(ext string) error {
	allowedExtensions := allowedExtensionsForManifest()
	for _, v := range allowedExtensions {
		if strings.EqualFold(filepath.Ext(strings.TrimSpace(ext)), v) {
			return nil
		}
	}
	return fmt.Errorf("only %v manifests are supported at this time", allowedExtensions)
}

func allowedExtensionsForManifest() []string {
	return []string{".yaml", ".yml"}
}
