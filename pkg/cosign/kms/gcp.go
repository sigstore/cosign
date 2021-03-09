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
	"fmt"
	"strings"

	kms "cloud.google.com/go/kms/apiv1"
	"github.com/pkg/errors"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

type gcpDetails struct {
	projectID  string
	locationID string
	keyRing    string
	key        string
}

type GCPKMS struct {
	keyResourceID string
}

func (g *GCPKMS) Encrypt() error {
	return nil
}

// GCP KMS keyResourceID should be in the format
// "projects/[PROJECT_ID]/locations/[LOCATION]/keyRings/[KEY_RING]/cryptoKeys/[KEY]".
func (g *GCPKMS) CreateKey(ctx context.Context) error {
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return errors.Wrap(err, "new key management client")
	}
	deets, err := parseKeyResourceID(g.keyResourceID)
	if err != nil {
		return errors.Wrap(err, "parsing key resource ID")
	}
	if err := createKeyRing(ctx, client, deets); err != nil {
		return errors.Wrap(err, "creating key ring")
	}
	return createKey(ctx, client, deets)
}

func parseKeyResourceID(keyResourceID string) (gcpDetails, error) {
	details := strings.Split(keyResourceID, "/")
	if len(details) != 8 {
		return gcpDetails{}, errors.New("kms specification should be in the format gcpkms://projects/[PROJECT_ID]/locations/[LOCATION]/keyRings/[KEY_RING]/cryptoKeys/[KEY]")
	}
	return gcpDetails{
		projectID:  details[1],
		locationID: details[3],
		keyRing:    details[5],
		key:        details[7],
	}, nil
}

func createKeyRing(ctx context.Context, client *kms.KeyManagementClient, deets gcpDetails) error {
	getKeyRingRequest := &kmspb.GetKeyRingRequest{
		Name: fmt.Sprintf("projects/%s/locations/%s/keyRings/%s", deets.projectID, deets.locationID, deets.keyRing),
	}
	if result, err := client.GetKeyRing(ctx, getKeyRingRequest); err == nil {
		fmt.Printf("Key ring %s already exists in GCP KMS, moving on to creating key.\n", result.GetName())
		// key ring already exists, no need to create
		return err
	}
	// try to create key ring
	createKeyRingRequest := &kmspb.CreateKeyRingRequest{
		Parent:    fmt.Sprintf("projects/%s/locations/%s", deets.projectID, deets.locationID),
		KeyRingId: deets.keyRing,
	}
	result, err := client.CreateKeyRing(ctx, createKeyRingRequest)
	fmt.Printf("Created key ring %s in GCP KMS.\n", result.GetName())
	return err
}

func createKey(ctx context.Context, client *kms.KeyManagementClient, deets gcpDetails) error {
	getKeyRequest := &kmspb.GetCryptoKeyRequest{
		Name: fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s", deets.projectID, deets.locationID, deets.keyRing, deets.key),
	}
	if result, err := client.GetCryptoKey(ctx, getKeyRequest); err == nil {
		fmt.Printf("Key %s already exists in GCP KMS, skipping creation.\n", result.GetName())
		return nil
	}

	createKeyRequest := &kmspb.CreateCryptoKeyRequest{
		Parent:      fmt.Sprintf("projects/%s/locations/%s/keyRings/%s", deets.projectID, deets.locationID, deets.keyRing),
		CryptoKeyId: deets.key,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
			},
		},
	}
	result, err := client.CreateCryptoKey(ctx, createKeyRequest)
	if err != nil {
		return errors.Wrap(err, "creating crypto key")
	}
	fmt.Printf("Created key %s in GCP KMS\n", result.GetName())
	return nil
}
