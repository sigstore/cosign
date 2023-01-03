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

package dockerfile

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/sigstore/cosign/v2/cmd/cosign/cli/verify"
)

// VerifyDockerfileCommand verifies a signature on a supplied container image.
// nolint
type VerifyDockerfileCommand struct {
	verify.VerifyCommand
	BaseOnly bool
}

// Exec runs the verification command.
func (c *VerifyDockerfileCommand) Exec(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return flag.ErrHelp
	}

	dockerfile, err := os.Open(args[0])
	if err != nil {
		return fmt.Errorf("could not open Dockerfile: %w", err)
	}
	defer dockerfile.Close()

	images, err := getImagesFromDockerfile(dockerfile)
	if err != nil {
		return fmt.Errorf("failed extracting images from Dockerfile: %w", err)
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
		if strings.HasPrefix(strings.ToUpper(line), "FROM") ||
			strings.HasPrefix(strings.ToUpper(line), "COPY") {
			switch image := getImageFromLine(line); image {
			case "":
				continue
			case "scratch":
				fmt.Fprintln(os.Stderr, "- scratch image ignored")
			default:
				images = append(images, image)
			}
		}
	}
	if err := fileScanner.Err(); err != nil {
		return nil, err
	}
	return images, nil
}

func getImageFromLine(line string) string {
	if strings.HasPrefix(strings.ToUpper(line), "COPY") {
		// To support `COPY --from=image:latest /foo /bar` cases.
		if strings.Contains(line, "--from") {
			if img := getFromValue(line); img != "" {
				return img
			}
		}
		// If no value returned, it can be an environment variable or a stage name.
		line = strings.TrimPrefix(line, "COPY") // Remove "COPY" prefix
		line = strings.TrimSpace(line)
		line = strings.TrimPrefix(line, "--from") // Remove "--from" prefix
		foo := strings.Split(line, "=")           // Get image ref after "="
		if len(foo) != 2 {
			return ""
		}
		// To support `COPY --from=stage /foo/bar` cases.
		if strings.Contains(foo[1], " ") {
			return ""
		}
		return os.ExpandEnv(foo[1]) // Substitute templated vars
	}
	line = strings.TrimPrefix(line, "FROM") // Remove "FROM" prefix
	line = os.ExpandEnv(line)               // Substitute templated vars
	fields := strings.Fields(line)
	for i := len(fields) - 1; i > 0; i-- {
		// Remove the "AS" portion of line
		if strings.EqualFold(fields[i], "AS") {
			fields = fields[:i]
			break
		}
	}
	return fields[len(fields)-1] // The image should be the last portion of the line that remains
}

// getFromValue returns the value of the `--from=` directive in a Dockerfile.
// If the directive is not present or the value is not a valid image reference,
// an empty string is returned.
func getFromValue(input string) string {
	fromKey := "--from="
	fromIndex := strings.Index(input, fromKey)
	if fromIndex == -1 {
		return ""
	}

	valueStartIndex := fromIndex + len(fromKey)
	valueEndIndex := strings.Index(input[valueStartIndex:], " ")
	if valueEndIndex == -1 {
		return input[valueStartIndex:]
	}

	value := input[valueStartIndex : valueStartIndex+valueEndIndex]
	// In order to distinguish between `--from=my-custom-stage` and `--from=image:latest` cases,
	// we check if the value contains a `:` character to determine if it's a stage or an image.
	if strings.Contains(value, ":") {
		return value
	}
	return ""
}
