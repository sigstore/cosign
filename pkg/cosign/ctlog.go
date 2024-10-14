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

package cosign

import (
	"context"
	"fmt"

	"github.com/sigstore/cosign/v2/pkg/cosign/env"
	"github.com/sigstore/sigstore-go/pkg/root"
	tufv1 "github.com/sigstore/sigstore/pkg/tuf"
)

// This is the CT log public key target name
var (
	ctPublicKeyStr  = `ctfe.pub`
	ctPublicKeyDesc = `CT log public key`
)

// GetCTLogPubs retrieves trusted CTLog public keys from the embedded or cached
// TUF root. If expired, makes a network call to retrieve the updated targets.
// By default the public keys comes from TUF, but you can override this for test
// purposes by using an env variable `SIGSTORE_CT_LOG_PUBLIC_KEY_FILE`. If using
// an alternate, the file can be PEM, or DER format.
func GetCTLogPubs(ctx context.Context) (*TrustedTransparencyLogPubKeys, error) {
	publicKeys := NewTrustedTransparencyLogPubKeys()
	altCTLogPub := env.Getenv(env.VariableSigstoreCTLogPublicKeyFile)

	if altCTLogPub != "" {
		if err := addKeyFromFile(&publicKeys, altCTLogPub, ctPublicKeyDesc); err != nil {
			return nil, fmt.Errorf("error adding key from environment variable: %w", err)
		}
		return &publicKeys, nil
	}

	if useNewTUFClient() {
		opts, err := setTUFOpts()
		if err != nil {
			return nil, fmt.Errorf("error setting TUF options: %w", err)
		}
		trustedRoot, _ := root.NewLiveTrustedRoot(opts)
		if trustedRoot == nil {
			if err = addKeyFromTUF(&publicKeys, opts, ctPublicKeyStr, ctPublicKeyDesc); err != nil {
				return nil, fmt.Errorf("error adding CT log public key from TUF target: %w", err)
			}
			return &publicKeys, err
		}
		ctlogs := trustedRoot.CTLogs()
		for _, ct := range ctlogs {
			if err := publicKeys.AddTransparencyLogPubKey(ct.PublicKey); err != nil {
				return nil, fmt.Errorf("error adding CT log public key from trusted root: %w", err)
			}
		}
		return &publicKeys, err
	}
	if err := legacyAddKeyFromTUF(ctx, &publicKeys, tufv1.CTFE, []string{ctPublicKeyStr}, ctPublicKeyDesc); err != nil {
		return nil, fmt.Errorf("error adding CT log public key from TUF (v1) target: %w", err)
	}
	if len(publicKeys.Keys) == 0 {
		return nil, fmt.Errorf("none of the CT log public keys have been found")
	}
	return &publicKeys, nil
}
