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
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"hash/crc32"
	"io/ioutil"
	"os"
	"strings"

	kms "cloud.google.com/go/kms/apiv1"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/pkg/cosign"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type gcp struct {
	client        *kms.KeyManagementClient
	keyResourceID string
	projectID     string
	locationID    string
	keyRing       string
	key           string
}

func newGCP(ctx context.Context, keyResourceID string) (*gcp, error) {
	details := strings.Split(keyResourceID, "/")
	if len(details) != 8 {
		return nil, errors.New("kms specification should be in the format gcpkms://projects/[PROJECT_ID]/locations/[LOCATION]/keyRings/[KEY_RING]/cryptoKeys/[KEY]")
	}
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "new key management client")
	}
	return &gcp{
		client:        client,
		keyResourceID: keyResourceID,
		projectID:     details[1],
		locationID:    details[3],
		keyRing:       details[5],
		key:           details[7],
	}, nil
}

func (g *gcp) Sign(ctx context.Context, keyPath string,
	imageRef string, upload bool, payloadPath string,
	annotations map[string]string, kmsVal string, forceTlog bool) error {

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

	// get public key now
	publicKey, err := g.publicKey(ctx)
	if err != nil {
		return errors.Wrap(err, "getting public key")
	}

	// Calculate the digest of the message.
	digest := sha256.New()
	if _, err := digest.Write(payload); err != nil {
		return fmt.Errorf("failed to create digest: %v", err)
	}
	// Optional but recommended: Compute digest's CRC32C.
	crc32c := func(data []byte) uint32 {
		t := crc32.MakeTable(crc32.Castagnoli)
		return crc32.Checksum(data, t)
	}
	digestCRC32C := crc32c(digest.Sum(nil))

	name, err := g.keyVersionName(ctx)
	if err != nil {
		return errors.Wrap(err, "key version name")
	}
	req := &kmspb.AsymmetricSignRequest{
		Name: name,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{
				Sha256: digest.Sum(nil),
			},
		},
		DigestCrc32C: wrapperspb.Int64(int64(digestCRC32C)),
	}
	result, err := g.client.AsymmetricSign(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to sign digest: %v", err)
	}
	// Optional, but recommended: perform integrity verification on result.
	// For more details on ensuring E2E in-transit integrity to and from Cloud KMS visit:
	// https://cloud.google.com/kms/docs/data-integrity-guidelines
	if !result.VerifiedDigestCrc32C {
		return fmt.Errorf("AsymmetricSign: request corrupted in-transit")
	}
	if int64(crc32c(result.Signature)) != result.SignatureCrc32C.Value {
		return fmt.Errorf("AsymmetricSign: response corrupted in-transit")
	}

	signature := result.GetSignature()

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

	// Check if the image is public (no auth in Get)
	if _, err := remote.Get(ref); err != nil {
		//private image!
		if forceTlog {
			fmt.Println("force uploading signature of private image to tlog")
			return cosign.UploadTLog(signature, payload, publicKey)
		} else {
			fmt.Println("skipping upload of private image, use --force-tlog to upload")
			return nil
		}
	}
	if os.Getenv(cosign.TLogEnv) != "1" {
		return nil
	}
	return cosign.UploadTLog(signature, payload, publicKey)
}

func (g *gcp) publicKey(ctx context.Context) (*ecdsa.PublicKey, error) {
	name, err := g.keyVersionName(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "key version")
	}
	// Build the request.
	pkreq := &kmspb.GetPublicKeyRequest{Name: name}
	// Call the API.
	pk, err := g.client.GetPublicKey(ctx, pkreq)
	if err != nil {
		return nil, errors.Wrap(err, "public key")
	}
	p, _ := pem.Decode([]byte(pk.GetPem()))
	if p == nil {
		return nil, errors.New("pem.Decode failed")
	}
	publicKey, err := x509.ParsePKIXPublicKey(p.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}
	ecKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not rsa")
	}
	return ecKey, nil
}

// keyVersionName returns the first key version found for a key in KMS
// TODO: is there a better way to do this?
func (g *gcp) keyVersionName(ctx context.Context) (string, error) {
	req := &kmspb.ListCryptoKeyVersionsRequest{
		Parent: fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s", g.projectID, g.locationID, g.keyRing, g.key),
	}
	iterator := g.client.ListCryptoKeyVersions(ctx, req)

	// pick the first key version that is enabled
	var name string
	for {
		kv, err := iterator.Next()
		if err != nil {
			break
		}
		if kv.State == kmspb.CryptoKeyVersion_ENABLED {
			name = kv.GetName()
			break
		}
	}
	if name == "" {
		return "", errors.New("unable to find an enabled key version in GCP KMS, generate one via `cosign generate-key-pair`")
	}
	return name, nil
}

// GCP KMS keyResourceID should be in the format
// "projects/[PROJECT_ID]/locations/[LOCATION]/keyRings/[KEY_RING]/cryptoKeys/[KEY]".
func (g *gcp) CreateKey(ctx context.Context) error {
	if err := g.createKeyRing(ctx); err != nil {
		return errors.Wrap(err, "creating key ring")
	}
	return g.createKey(ctx)
}

func (g *gcp) createKeyRing(ctx context.Context) error {
	getKeyRingRequest := &kmspb.GetKeyRingRequest{
		Name: fmt.Sprintf("projects/%s/locations/%s/keyRings/%s", g.projectID, g.locationID, g.keyRing),
	}
	if result, err := g.client.GetKeyRing(ctx, getKeyRingRequest); err == nil {
		fmt.Printf("Key ring %s already exists in GCP KMS, moving on to creating key.\n", result.GetName())
		// key ring already exists, no need to create
		return err
	}
	// try to create key ring
	createKeyRingRequest := &kmspb.CreateKeyRingRequest{
		Parent:    fmt.Sprintf("projects/%s/locations/%s", g.projectID, g.locationID),
		KeyRingId: g.keyRing,
	}
	result, err := g.client.CreateKeyRing(ctx, createKeyRingRequest)
	fmt.Printf("Created key ring %s in GCP KMS.\n", result.GetName())
	return err
}

func (g *gcp) createKey(ctx context.Context) error {
	getKeyRequest := &kmspb.GetCryptoKeyRequest{
		Name: fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s", g.projectID, g.locationID, g.keyRing, g.key),
	}
	if result, err := g.client.GetCryptoKey(ctx, getKeyRequest); err == nil {
		fmt.Printf("Key %s already exists in GCP KMS, skipping creation.\n", result.GetName())
		return nil
	}

	createKeyRequest := &kmspb.CreateCryptoKeyRequest{
		Parent:      fmt.Sprintf("projects/%s/locations/%s/keyRings/%s", g.projectID, g.locationID, g.keyRing),
		CryptoKeyId: g.key,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
			},
		},
	}
	result, err := g.client.CreateCryptoKey(ctx, createKeyRequest)
	if err != nil {
		return errors.Wrap(err, "creating crypto key")
	}
	fmt.Printf("Created key %s in GCP KMS\n", result.GetName())
	return nil
}
