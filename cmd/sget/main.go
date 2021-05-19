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

package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/sigstore/cosign/cmd/sget/cli"
)

var (
	rootFlagSet = flag.NewFlagSet("sget", flag.ExitOnError)
	o           = rootFlagSet.String("o", "", "output file")
	keyRef      = rootFlagSet.String("key", "", "path to the public key file, URL, or KMS URI")
)

func main() {
	root := &ffcli.Command{
		ShortUsage: "sget [-key] <image reference>",
		FlagSet:    rootFlagSet,
		Exec: func(ctx context.Context, args []string) error {
			if len(args) != 1 {
				return flag.ErrHelp
			}
			rc, err := cli.SgetCmd(ctx, args[0], *keyRef)
			if err != nil {
				return err
			}
			defer rc.Close()
			wc, err := createSink(*o)
			if err != nil {
				return err
			}
			_, err = io.Copy(wc, rc)
			if err != nil {
				return err
			}
			return wc.Close()
		},
	}

	if err := root.Parse(os.Args[1:]); err != nil {
		printErrAndExit(err)
	}

	if err := root.Run(context.Background()); err != nil {
		printErrAndExit(err)
	}
}

func printErrAndExit(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}

func createSink(path string) (io.WriteCloser, error) {
	if path == "" {
		// When writing to stdout, buffer so we can check the digest first.
		return &buffered{os.Stdout, &bytes.Buffer{}}, nil
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
