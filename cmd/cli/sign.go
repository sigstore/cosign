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
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/tlog"
)

type annotationsMap struct {
	annotations map[string]string
}

func (a *annotationsMap) Set(s string) error {
	if a.annotations == nil {
		a.annotations = map[string]string{}
	}
	kvp := strings.SplitN(s, "=", 2)
	if len(kvp) != 2 {
		return fmt.Errorf("invalid flag: %s, expected key=value", s)
	}

	a.annotations[kvp[0]] = kvp[1]
	return nil
}

func (a *annotationsMap) String() string {
	s := []string{}
	for k, v := range a.annotations {
		s = append(s, fmt.Sprintf("%s=%s", k, v))
	}
	return strings.Join(s, ",")
}

func Sign() *ffcli.Command {
	var (
		flagset     = flag.NewFlagSet("cosign sign", flag.ExitOnError)
		key         = flagset.String("key", "", "path to the private key")
		upload      = flagset.Bool("upload", true, "whether to upload the signature")
		payloadPath = flagset.String("payload", "", "path to a payload file to use rather than generating one.")
		annotations = annotationsMap{}
	)
	flagset.Var(&annotations, "a", "extra key=value pairs to sign")
	return &ffcli.Command{
		Name:       "sign",
		ShortUsage: "cosign sign -key <key> [-payload <path>] [-a key=value] [-upload=true|false] <image uri>",
		ShortHelp:  "Sign the supplied container image",
		FlagSet:    flagset,
		Exec: func(ctx context.Context, args []string) error {
			if *key == "" {
				return flag.ErrHelp
			}

			if len(args) != 1 {
				return flag.ErrHelp
			}

			return SignCmd(ctx, *key, args[0], *upload, *payloadPath, annotations.annotations, getPass)
		},
	}
}

func SignCmd(ctx context.Context, keyPath string,
	imageRef string, upload bool, payloadPath string,
	annotations map[string]string, pf cosign.PassFunc) error {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return err
	}

	get, err := remote.Get(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return err
	}

	// The payload can be specified via a flag to skip generation.
	var payload []byte
	if payloadPath != "" {
		fmt.Fprintln(os.Stderr, "Using payload from:", payloadPath)
		payload, err = ioutil.ReadFile(payloadPath)
	} else {
		payload, err = cosign.Payload(get.Descriptor, annotations)
	}
	if err != nil {
		return err
	}

	pass, err := pf(false)
	if err != nil {
		return err
	}
	kb, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return errors.Wrapf(err, "reading %s", keyPath)
	}
	pk, err := cosign.LoadPrivateKey(kb, pass)
	if err != nil {
		return errors.Wrap(err, "loading private key")
	}

	h := sha256.Sum256(payload)
	signature, err := ecdsa.SignASN1(rand.Reader, pk, h[:])
	if err != nil {
		return errors.Wrap(err, "signing asn1")
	}

	if !upload {
		fmt.Println(base64.StdEncoding.EncodeToString(signature))
		return nil
	}

	// sha256:... -> sha256-...
	dstTag := ref.Context().Tag(cosign.Munge(get.Descriptor))

	fmt.Fprintln(os.Stderr, "Pushing signature to:", dstTag.String())
	if err := cosign.Upload(signature, payload, dstTag); err != nil {
		return err
	}

	pubKey, err := cosign.LoadPublicKeyFromPrivKey(pk)
	if err != nil {
		return errors.Wrap(err, "loading public key from priv key")
	}
	return tlog.Upload(signature, payload, pubKey)
}
