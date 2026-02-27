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

	"github.com/sigstore/cosign/v3/cmd/cosign/cli/verify"
	"github.com/sigstore/cosign/v3/internal/ui"
)

// VerifyCommand verifies a signature on a supplied container image
// nolint
type VerifyDockerfileCommand struct {
	verify.VerifyCommand
	BaseOnly bool
}

// Exec runs the verification command
func (c *VerifyDockerfileCommand) Exec(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return flag.ErrHelp
	}

	dockerfile, err := os.Open(args[0])
	if err != nil {
		return fmt.Errorf("could not open Dockerfile: %w", err)
	}
	defer dockerfile.Close()

	fc := newFinderCache()
	images, err := fc.getImagesFromDockerfile(ctx, dockerfile)
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

type finderCache struct {
	Env    map[string]string
	Stages []string
}

func newFinderCache() *finderCache {
	return &finderCache{
		Env:    map[string]string{},
		Stages: []string{},
	}
}

func (fc *finderCache) isStage(input string) (found bool) {
	for _, s := range fc.Stages {
		if s == input {
			found = true
			break
		}
	}
	return found
}

func (fc *finderCache) getImagesFromDockerfile(ctx context.Context, dockerfile io.Reader) ([]string, error) {
	var images []string
	fileScanner := bufio.NewScanner(dockerfile)
	for fileScanner.Scan() {
		line := strings.TrimSpace(fileScanner.Text())
		lineUpper := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(lineUpper, "FROM"):
			switch image := fc.getImageFromLine(line); image {
			case "scratch":
				ui.Infof(ctx, "- scratch image ignored")
			default:
				images = append(images, image)
			}
		case strings.HasPrefix(lineUpper, "COPY"):
			if image := fc.getImageFromCopyLine(line); image != "" {
				images = append(images, image)
			}
		case strings.HasPrefix(lineUpper, "ENV") || strings.HasPrefix(lineUpper, "ARG"):
			fc.getEnvAndArgs(line)
		}
	}
	if err := fileScanner.Err(); err != nil {
		return nil, err
	}
	return images, nil
}

func (fc *finderCache) getImageFromLine(line string) string {
	line = strings.TrimPrefix(line, "FROM")          // Remove "FROM" prefix
	line = os.Expand(line, func(key string) string { // Substitute templated vars
		if val, ok := fc.Env[key]; ok {
			return val
		}
		// NOTE not using pkg/cosign/env due to env not relating to cosign
		//nolint:forbidigo
		if val, ok := os.LookupEnv(key); ok {
			return val
		}
		return ""
	})
	fields := strings.Fields(line)
	for i := len(fields) - 1; i > 0; i-- {
		// Remove the "AS" portion of line
		if strings.EqualFold(fields[i], "AS") {
			fc.Stages = append(fc.Stages, fields[i+1])
			fields = fields[:i]
			break
		}
	}
	return fields[len(fields)-1] // The image should be the last portion of the line that remains
}

func (fc *finderCache) getImageFromCopyLine(line string) string {
	line = strings.TrimPrefix(line, "COPY")          // Remove "COPY" prefix
	line = os.Expand(line, func(key string) string { // Substitute templated vars
		if val, ok := fc.Env[key]; ok {
			return val
		}
		// NOTE not using pkg/cosign/env due to env not relating to cosign
		//nolint:forbidigo
		if val, ok := os.LookupEnv(key); ok {
			return val
		}
		return ""
	})
	var image string
	fields := strings.Fields(line)
	for _, f := range fields {
		if !strings.Contains(f, "--from=") {
			continue
		}
		split := strings.Split(f, "=")
		if len(split) < 2 {
			continue
		}
		if fc.isStage(split[1]) {
			continue
		}
		image = split[1]
		break
	}
	return image
}

func (fc *finderCache) getEnvAndArgs(line string) {
	line = strings.TrimPrefix(line, "ENV")           // Remove "ENV" prefix
	line = strings.TrimPrefix(line, "ARG")           // Remove "ARG" prefix
	line = os.Expand(line, func(key string) string { // Substitute templated vars
		if val, ok := fc.Env[key]; ok {
			return val
		}
		// NOTE not using pkg/cosign/env due to env not relating to cosign
		//nolint:forbidigo
		if val, ok := os.LookupEnv(key); ok {
			return val
		}
		return ""
	})
	fields := strings.Fields(line)
	for _, f := range fields {
		keyvalue := strings.Split(f, "=")
		if len(keyvalue) < 2 {
			continue
		}
		key := strings.Trim(keyvalue[0], " ")
		value := strings.Trim(keyvalue[1], " ")
		fc.Env[key] = value
	}
}
