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

package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/peterbourgon/ff/v3/ffcli"

	"github.com/sigstore/cosign/pkg/cosign"
)

func Download() *ffcli.Command {
	var (
		flagset = flag.NewFlagSet("cosign download", flag.ExitOnError)
	)
	return &ffcli.Command{
		Name:       "download",
		ShortUsage: "cosign download <image uri>",
		ShortHelp:  "Download signatures from the supplied container image",
		FlagSet:    flagset,
		Exec: func(ctx context.Context, args []string) error {
			if len(args) != 1 {
				return flag.ErrHelp
			}
			return DownloadCmd(ctx, args[0])
		},
	}
}

func DownloadCmd(ctx context.Context, imageRef string) error {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return err
	}

	signatures, _, err := cosign.FetchSignatures(ctx, ref)
	if err != nil {
		return err
	}
	for _, sig := range signatures {
		b, err := json.Marshal(sig)
		if err != nil {
			return err
		}
		fmt.Println(string(b))
	}
	return nil
}
