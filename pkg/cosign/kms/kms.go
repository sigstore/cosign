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

package kms

import (
	"context"
	"crypto/ecdsa"
	"fmt"

	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/sigstore/cosign/pkg/cosign/kms/gcp"
)

type KMS interface {
	// CreateKey is responsible for creating an asymmetric key pair
	// with the ECDSA algorithm on the P-256 Curve with a SHA-256 digest
	CreateKey(context.Context) (*ecdsa.PublicKey, error)

	// Sign is responsible for signing an image via the keys
	// stored in KMS
	Sign(ctx context.Context, img *remote.Descriptor, payload []byte) (signature []byte, err error)

	// SignBlob is responsible for signing a blob
	// SignBlob(ctx context.Context, payload []byte) (signature []byte, err error)

	// PublicKey returns the public key stored in the KMS
	PublicKey(ctx context.Context) (*ecdsa.PublicKey, error)
}

func Get(ctx context.Context, keyResourceID string) (KMS, error) {
	if err := gcp.ValidReference(keyResourceID); err != nil {
		return nil, fmt.Errorf("could not parse kms reference (only GCP supported for now): %w", err)
	}
	return gcp.NewGCP(ctx, keyResourceID)
}
