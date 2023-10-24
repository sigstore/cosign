// Copyright 2023 the Sigstore Authors.
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

package copy

import (
	"context"
	"testing"

	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
)

func TestCopyAttachmentTagPrefix(t *testing.T) {
	ctx := context.Background()

	refOpts := options.ReferenceOptions{
		TagPrefix: "test-tag",
	}

	srcImg := "alpine"
	destImg := "test-alpine"

	err := CopyCmd(ctx, options.RegistryOptions{
		RefOpts: refOpts,
	}, srcImg, destImg, false, true, "", "")
	if err == nil {
		t.Fatal("failed to copy with attachment-tag-prefix")
	}
}

func TestCopyPlatformOpt(t *testing.T) {
	ctx := context.Background()

	srcImg := "alpine"
	destImg := "test-alpine"

	err := CopyCmd(ctx, options.RegistryOptions{}, srcImg, destImg, false, true, "", "linux/amd64")
	if err == nil {
		t.Fatal("failed to copy with platform")
	}
}
