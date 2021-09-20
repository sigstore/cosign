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

package manifest

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/util/yaml"

	"github.com/sigstore/cosign/cmd/cosign/cli/verify"
)

// VerifyManifestCommand verifies all image signatures on a supplied k8s resource
type VerifyManifestCommand struct {
	verify.VerifyCommand
}

// VerifyManifest builds and returns an ffcli command
func VerifyManifest() *ffcli.Command {
	cmd := VerifyManifestCommand{}
	flagset := flag.NewFlagSet("cosign manifest verify", flag.ExitOnError)
	verify.ApplyVerifyFlags(&cmd.VerifyCommand, flagset)

	return &ffcli.Command{
		Name:       "verify",
		ShortUsage: "cosign manifest verify -key <key path>|<key url>|<kms uri> <path/to/manifest>",
		ShortHelp:  "Verify all signatures of images specified in the manifest",
		LongHelp: `Verify all signature of images in a Kubernetes resource manifest by checking claims
against the transparency log.

EXAMPLES
  # verify cosign claims and signing certificates on images in the manifest
  cosign manifest verify <path/to/my-deployment.yaml>

  # additionally verify specified annotations
  cosign manifest verify -a key1=val1 -a key2=val2 <path/to/my-deployment.yaml>

  # (experimental) additionally, verify with the transparency log
  COSIGN_EXPERIMENTAL=1 cosign manifest verify <path/to/my-deployment.yaml>

  # verify images with public key
  cosign manifest verify -key cosign.pub <path/to/my-deployment.yaml>

  # verify images with public key provided by URL
  cosign manifest verify -key https://host.for/<FILE> <path/to/my-deployment.yaml>

  # verify images with public key stored in Azure Key Vault
  cosign manifest verify -key azurekms://[VAULT_NAME][VAULT_URI]/[KEY] <path/to/my-deployment.yaml>

  # verify images with public key stored in AWS KMS
  cosign manifest verify -key awskms://[ENDPOINT]/[ID/ALIAS/ARN] <path/to/my-deployment.yaml>

  # verify images with public key stored in Google Cloud KMS
  cosign manifest verify -key gcpkms://projects/[PROJECT]/locations/global/keyRings/[KEYRING]/cryptoKeys/[KEY] <path/to/my-deployment.yaml>

  # verify images with public key stored in Hashicorp Vault
  cosign manifest verify -key hashivault://[KEY] <path/to/my-deployment.yaml>`,

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
		return fmt.Errorf("could not read manifest: %w", err)
	}

	images, err := getImagesFromYamlManifest(manifest)
	if err != nil {
		return fmt.Errorf("unable to extract the container image references in the manifest %w", err)
	}
	if len(images) == 0 {
		return errors.New("no images found in manifest")
	}
	fmt.Fprintf(os.Stderr, "Extracted image(s): %s\n", strings.Join(images, ", "))

	return c.VerifyCommand.Exec(ctx, images)
}

// unionImagesKind is the union type that match PodSpec, PodSpecTemplate, and
// JobSpecTemplate; but filtering all keys except for `Image`.
type unionImagesKind struct {
	Spec struct {
		// PodSpec
		imageContainers `json:",inline"`
		// PodSpecTemplate
		Template struct {
			Spec struct {
				imageContainers `json:",inline"`
			}
		}
		// JobSpecTemplate
		JobTemplate struct {
			Spec struct {
				Template struct {
					Spec struct {
						imageContainers `json:",inline"`
					}
				}
			}
		}
	}
}

// imageContainers is a wrapper for `containers[].image` and `initContainers[].image`
type imageContainers struct {
	Containers []struct {
		Image string
	}
	InitContainers []struct {
		Image string
	}
}

func (uik *unionImagesKind) images() []string {
	images := []string(nil)
	var addImage = func(ic *imageContainers) {
		for _, c := range ic.InitContainers {
			if len(c.Image) > 0 {
				images = append(images, c.Image)
			}
		}
		for _, c := range ic.Containers {
			if len(c.Image) > 0 {
				images = append(images, c.Image)
			}
		}
	}

	// Pod
	addImage(&uik.Spec.imageContainers)

	// Deployment, ReplicaSet, StatefulSet, DaemonSet, Job
	addImage(&uik.Spec.Template.Spec.imageContainers)

	// CronJob
	addImage(&uik.Spec.JobTemplate.Spec.Template.Spec.imageContainers)

	return images
}

func getImagesFromYamlManifest(manifest []byte) ([]string, error) {
	dec := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(manifest), 4096)
	var images []string

	for {
		ic := unionImagesKind{}
		if err := dec.Decode(&ic); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return images, errors.New("unable to decode the manifest")
		}
		images = append(images, ic.images()...)
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
