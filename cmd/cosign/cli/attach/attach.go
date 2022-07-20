// Copyright 2021 The Sigstore Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package attach

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	ssldsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
	"github.com/sigstore/cosign/pkg/oci/static"
	"github.com/sigstore/cosign/pkg/types"
)

func AttestationCmd(ctx context.Context, regOpts options.RegistryOptions, signedPayloads []string, imageRef string) error {
	ociremoteOpts, err := regOpts.ClientOpts(ctx)
	if err != nil {
		return fmt.Errorf("constructing client options: %w", err)
	}

	for _, payload := range signedPayloads {
		if err := attachAttestation(ociremoteOpts, payload, imageRef); err != nil {
			return fmt.Errorf("attaching payload from %s: %w", payload, err)
		}
	}

	return nil
}

func attachAttestation(remoteOpts []ociremote.Option, signedPayload, imageRef string) error {
	fmt.Fprintf(os.Stderr, "Using payload from: %s", signedPayload)
	attestation, err := os.Open(signedPayload)
	if err != nil {
		return err
	}

	env := ssldsse.Envelope{}
	decoder := json.NewDecoder(attestation)
	for decoder.More() {
		if err := decoder.Decode(&env); err != nil {
			return err
		}

		payload, err := json.Marshal(env)
		if err != nil {
			return err
		}

		if env.PayloadType != types.IntotoPayloadType {
			return fmt.Errorf("invalid payloadType %s on envelope. Expected %s", env.PayloadType, types.IntotoPayloadType)
		}

		if len(env.Signatures) == 0 {
			return fmt.Errorf("could not attach attestation without having signatures")
		}

		ref, err := name.ParseReference(imageRef)
		if err != nil {
			return err
		}
		digest, err := ociremote.ResolveDigest(ref, remoteOpts...)
		if err != nil {
			return err
		}
		// Overwrite "ref" with a digest to avoid a race where we use a tag
		// multiple times, and it potentially points to different things at
		// each access.
		ref = digest // nolint

		opts := []static.Option{static.WithLayerMediaType(types.DssePayloadType)}
		att, err := static.NewAttestation(payload, opts...)
		if err != nil {
			return err
		}

		se, err := ociremote.SignedEntity(digest, remoteOpts...)
		if err != nil {
			return err
		}

		newSE, err := mutate.AttachAttestationToEntity(se, att)
		if err != nil {
			return err
		}

		// Publish the signatures associated with this entity
		err = ociremote.WriteAttestations(digest.Repository, newSE, remoteOpts...)
		if err != nil {
			return err
		}
	}
	return nil
}
