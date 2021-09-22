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

package attach

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/peterbourgon/ff/v3/ffcli"

	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	ociremote "github.com/sigstore/cosign/internal/oci/remote"
	"github.com/sigstore/cosign/internal/oci/static"
	cremote "github.com/sigstore/cosign/pkg/cosign/remote"
	sigPayload "github.com/sigstore/sigstore/pkg/signature/payload"
)

func Signature() *ffcli.Command {
	var (
		flagset   = flag.NewFlagSet("cosign attach signature", flag.ExitOnError)
		signature = flagset.String("signature", "", "the signature, path to the signature, or {-} for stdin")
		payload   = flagset.String("payload", "", "path to the payload covered by the signature (if using another format)")
		regOpts   options.RegistryOpts
	)
	options.ApplyRegistryFlags(&regOpts, flagset)
	return &ffcli.Command{
		Name:       "signature",
		ShortUsage: "cosign attach signature <image uri>",
		ShortHelp:  "Attach signatures to the supplied container image",
		FlagSet:    flagset,
		Exec: func(ctx context.Context, args []string) error {
			if len(args) != 1 {
				return flag.ErrHelp
			}

			return SignatureCmd(ctx, regOpts, *signature, *payload, args[0])
		},
	}
}

func SignatureCmd(ctx context.Context, regOpts options.RegistryOpts, sigRef, payloadRef, imageRef string) error {
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

	digest, err := ociremote.ResolveDigest(ref, regOpts.ClientOpts(ctx)...)
	if err != nil {
		return err
	}

	var payload []byte
	if payloadRef == "" {
		payload, err = (&sigPayload.Cosign{Image: digest}).MarshalJSON()
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

	dstRef, err := ociremote.SignatureTag(digest, regOpts.ClientOpts(ctx)...)
	if err != nil {
		return err
	}

	sig, err := static.NewSignature(payload, base64.StdEncoding.EncodeToString(sigBytes))
	if err != nil {
		return err
	}

	return cremote.UploadSignature(sig, dstRef, cremote.UploadOpts{RemoteOpts: regOpts.GetRegistryClientOpts(ctx)})
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
