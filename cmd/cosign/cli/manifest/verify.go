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
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/util/yaml"

	"github.com/sigstore/cosign/cmd/cosign/cli/verify"
)

// VerifyManifestCommand verifies all image signatures on a supplied k8s resource
type VerifyManifestCommand struct {
	verify.VerifyCommand
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
	manifest, err := os.ReadFile(manifestPath)
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
