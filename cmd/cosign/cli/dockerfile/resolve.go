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

package dockerfile

import (
	"bufio"
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v2/pkg/oci/remote"

	"github.com/pkg/errors"
)

// ResolveDockerfileCommand rewrites the Dockerfile
// base images to FROM <digest>.
type ResolveDockerfileCommand struct {
	Output string
}

// Exec runs the resolve dockerfile command
func (c *ResolveDockerfileCommand) Exec(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return flag.ErrHelp
	}

	dockerfile, err := os.Open(args[0])
	if err != nil {
		return fmt.Errorf("could not open Dockerfile: %w", err)
	}
	defer dockerfile.Close()

	resolvedDockerfile, err := resolveDigest(dockerfile)
	if err != nil {
		return fmt.Errorf("failed extracting images from Dockerfile: %w", err)
	}

	if c.Output != "" {
		if err := os.WriteFile(c.Output, resolvedDockerfile, 0600); err != nil {
			return fmt.Errorf("failed writing resolved Dockerfile: %w", err)
		}
	} else {
		fmt.Fprintln(os.Stdout, string(resolvedDockerfile))
	}

	return nil
}

func resolveDigest(dockerfile io.Reader) ([]byte, error) {
	fileScanner := bufio.NewScanner(dockerfile)
	tmp := bytes.NewBuffer([]byte{})

	for fileScanner.Scan() {
		line := strings.TrimSpace(fileScanner.Text())

		if strings.HasPrefix(strings.ToUpper(line), "FROM") ||
			strings.HasPrefix(strings.ToUpper(line), "COPY") {
			switch image := getImageFromLine(line); image {
			case "scratch":
				tmp.WriteString(line)
			default:
				ref, err := name.ParseReference(image)
				if err != nil {
					// we should not return err here since
					// we can define the image refs smth like
					// i.e., FROM alpine:$(TAG), FROM $(IMAGE), etc.
					// TODO: support parameter substitution by passing a `--build-arg` flag
					fmt.Fprintf(os.Stderr, "WARNING: parameter substitution for images is not supported yet. consider setting all environment variables before resolving the Dockerfile. Image: %s.\n", image)
					tmp.WriteString(line)
					tmp.WriteString("\n")
					continue
				}

				d, err := remote.ResolveDigest(ref)
				if err != nil {
					return nil, errors.Wrap(err, "resolving digest")
				}

				// rewrite the image as follows:
				// alpine:3.13 => index.docker.io/library/alpine@sha256:026f721af4cf2843e07bba648e158fb35ecc876d822130633cc49f707f0fc88c
				tmp.WriteString(strings.ReplaceAll(line, image, d.String()))
			}
		} else {
			tmp.WriteString(line)
		}
		tmp.WriteString("\n")
	}

	return tmp.Bytes(), nil
}
