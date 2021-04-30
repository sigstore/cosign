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
	"encoding/base64"
	"errors"
	"flag"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/peterbourgon/ff/v3/ffcli"

	"github.com/sigstore/cosign/pkg/cosign"
	cremote "github.com/sigstore/cosign/pkg/cosign/remote"
	sigPayload "github.com/sigstore/sigstore/pkg/signature/payload"
)

func Upload() *ffcli.Command {
	var (
		flagset   = flag.NewFlagSet("cosign upload", flag.ExitOnError)
		signature = flagset.String("signature", "", "the signature, path to the signature, or {-} for stdin")
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

	b64SigBytes, err := signatureBytes(sigRef)
	if err != nil {
		return err
	} else if len(b64SigBytes) == 0 {
		return errors.New("empty signature")
	}

	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return err
	}

	auth := remote.WithAuthFromKeychain(authn.DefaultKeychain)

	get, err := remote.Get(ref, auth)
	if err != nil {
		return err
	}
	repo := ref.Context()
	img := repo.Digest(get.Digest.String())

	dstRef, err := cosign.DestinationRef(ref, get)
	if err != nil {
		return err
	}

	var payload []byte
	if payloadRef == "" {
		payload, err = (&sigPayload.Cosign{Image: img}).MarshalJSON()
	} else {
		payload, err = ioutil.ReadFile(filepath.Clean(payloadRef))
	}
	if err != nil {
		return err
	}

	// This expects it to not be base64 encoded, so decode first
	sigBytes, err := base64.StdEncoding.DecodeString(string(b64SigBytes))
	if err != nil {
		return err
	}
	if _, err := cremote.UploadSignature(ctx, sigBytes, payload, dstRef, cremote.UploadOpts{RemoteOpts: []remote.Option{auth}}); err != nil {
		return err
	}
	return nil
}

type SignatureArgType uint8

const (
	StdinSignature SignatureArgType = iota
	RawSignature   SignatureArgType = iota
	FileSignature  SignatureArgType = iota
)

func signatureBytes(sigRef string) ([]byte, error) {
	// sigRef can be "-", a string or a file.
	switch signatureType(sigRef) {
	case StdinSignature:
		return ioutil.ReadAll(os.Stdin)
	case RawSignature:
		return []byte(sigRef), nil
	case FileSignature:
		return ioutil.ReadFile(filepath.Clean(sigRef))
	default:
		return nil, errors.New("unknown signature arg type")
	}
}

func signatureType(sigRef string) SignatureArgType {
	switch {
	case sigRef == "-":
		return StdinSignature
	case signatureFileNotExists(sigRef):
		return RawSignature
	default:
		return FileSignature
	}
}

func signatureFileNotExists(sigRef string) bool {
	_, err := os.Stat(sigRef)
	return os.IsNotExist(err)
}
