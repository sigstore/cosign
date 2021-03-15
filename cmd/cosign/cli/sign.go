/*
Copyright The Sigstore Authors

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
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/kms"
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
		kmsVal      = flagset.String("kms", "", "sign via a private key stored in a KMS")
		upload      = flagset.Bool("upload", true, "whether to upload the signature")
		payloadPath = flagset.String("payload", "", "path to a payload file to use rather than generating one.")
		force       = flagset.Bool("f", false, "skip warnings and confirmations")
		annotations = annotationsMap{}
	)
	flagset.Var(&annotations, "a", "extra key=value pairs to sign")
	return &ffcli.Command{
		Name:       "sign",
		ShortUsage: "cosign sign -key <key> [-payload <path>] [-a key=value] [-upload=true|false] [-f] <image uri>",
		ShortHelp:  "Sign the supplied container image",
		FlagSet:    flagset,
		Exec: func(ctx context.Context, args []string) error {
			if *key == "" && *kmsVal == "" {
				return flag.ErrHelp
			}

			if len(args) != 1 {
				return flag.ErrHelp
			}

			return SignCmd(ctx, *key, args[0], *upload, *payloadPath, annotations.annotations, *kmsVal, getPass, *force)
		},
	}
}

// KeyParseError is an error returned when an incorrect set of key flags
// are parsed by the CLI
type KeyParseError struct{}

func (e *KeyParseError) Error() string {
	return "either local key path (-key) or KMS path (-kms) must be provided, not both"
}

func SignCmd(ctx context.Context, keyPath string,
	imageRef string, upload bool, payloadPath string,
	annotations map[string]string, kmsVal string, pf cosign.PassFunc, force bool) error {

	if keyPath != "" && kmsVal != "" {
		return &KeyParseError{}
	}

	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return errors.Wrap(err, "parsing reference")
	}
	get, err := remote.Get(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return errors.Wrap(err, "getting remote image")
	}
	// The payload can be specified via a flag to skip generation.
	var payload []byte
	if payloadPath != "" {
		fmt.Fprintln(os.Stderr, "Using payload from:", payloadPath)
		payload, err = ioutil.ReadFile(filepath.Clean(payloadPath))
	} else {
		payload, err = cosign.Payload(get.Descriptor, annotations)
	}
	if err != nil {
		return errors.Wrap(err, "payload")
	}

	var signature []byte
	var publicKey *ecdsa.PublicKey
	if kmsVal != "" {
		k, err := kms.Get(ctx, kmsVal)
		if err != nil {
			return err
		}
		signature, err = k.Sign(ctx, get, payload)
		if err != nil {
			return errors.Wrap(err, "signing")
		}
		publicKey, err = k.PublicKey(ctx)
		if err != nil {
			return errors.Wrap(err, "getting public key")
		}
	} else {
		signature, publicKey, err = sign(ctx, get, keyPath, payload, pf)
	}
	if err != nil {
		return errors.Wrap(err, "signing")
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

	if os.Getenv(cosign.ExperimentalEnv) != "1" {
		return nil
	}

	// Check if the image is public (no auth in Get)
	if !force {
		if _, err := remote.Get(ref); err != nil {
			fmt.Println("warning: uploading to the public transparency log for a private image, please confirm: (Y/N)")
			var response string
			if _, err := fmt.Scanln(&response); err != nil {
				return err
			}
			if response != "Y" {
				fmt.Println("not uploading to transparency log")
				return nil
			}
		}
	}
	return cosign.UploadTLog(signature, payload, publicKey)
}

func sign(ctx context.Context, img *remote.Descriptor, keyPath string, payload []byte, pf cosign.PassFunc) (signature []byte, publicKey *ecdsa.PublicKey, err error) {
	kb, err := ioutil.ReadFile(filepath.Clean(keyPath))
	if err != nil {
		return
	}
	pass, err := pf(false)
	if err != nil {
		return
	}
	pk, err := cosign.LoadPrivateKey(kb, pass)
	if err != nil {
		return
	}

	h := sha256.Sum256(payload)
	signature, err = ecdsa.SignASN1(rand.Reader, pk, h[:])
	if err != nil {
		return
	}
	publicKey = &pk.PublicKey
	return
}
