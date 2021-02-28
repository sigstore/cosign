/*
Copyright The Rekor Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cli

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"io/ioutil"
	"os"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/sigstore/cosign/pkg/cosign"
)

func Upload() *ffcli.Command {
	var (
		flagset   = flag.NewFlagSet("cosign upload", flag.ExitOnError)
		signature = flagset.String("signature", "", "path to the signature or {-} for stdin")
		payload   = flagset.String("payload", "", "path to the payload covered by the signature (if using another format)")
	)
	return &ffcli.Command{
		Name:       "upload",
		ShortUsage: "cosign upload <image uri>",
		ShortHelp:  "upload signatures to the supplied container image",
		FlagSet:    flagset,
		Exec: func(ctx context.Context, args []string) error {
			if len(args) != 1 {
				return flag.ErrHelp
			}

			return UploadCmd(ctx, *signature, *payload, args[0])
		},
	}
}

func UploadCmd(ctx context.Context, sigRef, payloadRef, imageRef string) error {
	var b64SigBytes []byte
	var err error

	// This can be "-", a file or a string.
	if sigRef == "-" {
		b64SigBytes, err = ioutil.ReadAll(os.Stdin)
	} else if _, err = os.Stat(sigRef); os.IsNotExist(err) {
		b64SigBytes = []byte(sigRef)
	} else {
		b64SigBytes, err = ioutil.ReadFile(sigRef)
	}
	if err != nil {
		return err
	}
	if len(b64SigBytes) == 0 {
		return errors.New("empty signature")
	}

	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return err
	}

	get, err := remote.Get(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return err
	}

	dstTag := ref.Context().Tag(cosign.Munge(get.Descriptor))

	var payload []byte
	if payloadRef == "" {
		payload, err = cosign.Payload(get.Descriptor, nil)
	} else {
		payload, err = ioutil.ReadFile(payloadRef)
	}
	if err != nil {
		return err
	}

	// This expects it to not be base64 encoded, so decode first
	sigBytes, err := base64.StdEncoding.DecodeString(string(b64SigBytes))
	if err != nil {
		return err
	}
	return cosign.Upload(sigBytes, payload, dstTag)
}
