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

// Deprecated: This package is deprecated and will be removed in a future release.
package cli

import (
	"bytes"
	"errors"
	"io"
	"os"

	"github.com/spf13/cobra"
	"sigs.k8s.io/release-utils/version"

	"github.com/sigstore/cosign/cmd/sget/cli/options"
	"github.com/sigstore/cosign/pkg/sget"
)

var (
	ro = &options.RootOptions{}
)

func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sget <image reference>",
		Short: "sget [--key <key reference>] <image reference>",
		Long:  `sget is DEPRECATED in the cosign repo -- see https://github.com/sigstore/sget for the new tool.`,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return errors.New("a single image reference is required")
			}
			ro.ImageRef = args[0]
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			wc, err := createSink(ro.OutputFile)
			if err != nil {
				return err
			}
			defer wc.Close()
			return sget.New(ro.ImageRef, ro.PublicKey, wc).Do(cmd.Context())
		},
	}
	ro.AddFlags(cmd)

	// Add sub-commands.
	cmd.AddCommand(version.Version())

	return cmd
}

func createSink(path string) (io.WriteCloser, error) {
	if path == "" {
		// When writing to stdout, buffer so we can check the digest first.
		return &buffered{w: os.Stdout, buf: &bytes.Buffer{}}, nil
	}

	return os.Create(path)
}

type buffered struct {
	w   io.Writer
	buf *bytes.Buffer
}

func (b *buffered) Write(p []byte) (n int, err error) {
	return b.buf.Write(p)
}

func (b *buffered) Close() error {
	_, err := io.Copy(b.w, b.buf)
	return err
}
