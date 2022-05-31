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
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"

	"github.com/sigstore/cosign/pkg/cosign/bundle"
	"github.com/sigstore/cosign/pkg/cosign/tuf"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/client/index"
	"github.com/sigstore/rekor/pkg/generated/models"
	hashedrekord_v001 "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
	intoto_v001 "github.com/sigstore/rekor/pkg/types/intoto/v0.0.1"
)

// This is the rekor public key target name
var rekorTargetStr = `rekor.pub`

// RekorPubKey contains the ECDSA verification key and the current status
// of the key according to TUF metadata, whether it's active or expired.
type RekorPubKey struct {
	PubKey *ecdsa.PublicKey
	Status tuf.StatusKind
}

const (
	// If specified, you can specify an oob Public Key that Rekor uses using
	// this ENV variable.
	altRekorPublicKey = "SIGSTORE_REKOR_PUBLIC_KEY"
	// Add Rekor API Public Key
	// If specified, will fetch the Rekor Public Key from the specified Rekor
	// server and add it to RekorPubKeys.
	// TODO(vaikas): Implement storing state like Rekor does so that if tree
	// state ever changes, it will make lots of noise.
	addRekorPublicKeyFromRekor = "SIGSTORE_TRUST_REKOR_API_PUBLIC_KEY"
)

// getLogID generates a SHA256 hash of a DER-encoded public key.
func getLogID(pub crypto.PublicKey) (string, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(pubBytes)
	return hex.EncodeToString(digest[:]), nil
}

// GetRekorPubs retrieves trusted Rekor public keys from the embedded or cached
// TUF root. If expired, makes a network call to retrieve the updated targets.
// There is an Env variable that can be used to override this behaviour:
// SIGSTORE_REKOR_PUBLIC_KEY - If specified, location of the file that contains
// the Rekor Public Key on local filesystem
func GetRekorPubs(ctx context.Context) (map[string]RekorPubKey, error) {
	publicKeys := make(map[string]RekorPubKey)
	altRekorPub := os.Getenv(altRekorPublicKey)

	if altRekorPub != "" {
		fmt.Fprintf(os.Stderr, "**Warning** Using a non-standard public key for Rekor: %s\n", altRekorPub)
		raw, err := os.ReadFile(altRekorPub)
		if err != nil {
			return nil, fmt.Errorf("error reading alternate Rekor public key file: %w", err)
		}
		extra, err := PemToECDSAKey(raw)
		if err != nil {
			return nil, fmt.Errorf("error converting PEM to ECDSAKey: %w", err)
		}
		keyID, err := getLogID(extra)
		if err != nil {
			return nil, fmt.Errorf("error generating log ID: %w", err)
		}
		publicKeys[keyID] = RekorPubKey{PubKey: extra, Status: tuf.Active}
	} else {
		tufClient, err := tuf.NewFromEnv(ctx)
		if err != nil {
			return nil, err
		}
		defer tufClient.Close()
		targets, err := tufClient.GetTargetsByMeta(tuf.Rekor, []string{rekorTargetStr})
		if err != nil {
			return nil, err
		}
		for _, t := range targets {
			rekorPubKey, err := PemToECDSAKey(t.Target)
			if err != nil {
				return nil, fmt.Errorf("pem to ecdsa: %w", err)
			}
			keyID, err := getLogID(rekorPubKey)
			if err != nil {
				return nil, fmt.Errorf("error generating log ID: %w", err)
			}
			publicKeys[keyID] = RekorPubKey{PubKey: rekorPubKey, Status: t.Status}
		}
	}
	if len(publicKeys) == 0 {
		return nil, errors.New("none of the Rekor public keys have been found")
	}

	return publicKeys, nil
}

// TLogUpload will upload the signature, public key and payload to the transparency log.
func TLogUpload(ctx context.Context, rekorClient *client.Rekor, signature, payload []byte, pemBytes []byte) (*models.LogEntryAnon, error) {
	re := rekorEntry(payload, signature, pemBytes)
	returnVal := models.Hashedrekord{
		APIVersion: swag.String(re.APIVersion()),
		Spec:       re.HashedRekordObj,
	}
	return doUpload(ctx, rekorClient, &returnVal)
}

// TLogUploadInTotoAttestation will upload and in-toto entry for the signature and public key to the transparency log.
func TLogUploadInTotoAttestation(ctx context.Context, rekorClient *client.Rekor, signature, pemBytes []byte) (*models.LogEntryAnon, error) {
	e := intotoEntry(signature, pemBytes)
	returnVal := models.Intoto{
		APIVersion: swag.String(e.APIVersion()),
		Spec:       e.IntotoObj,
	}
	return doUpload(ctx, rekorClient, &returnVal)
}

func doUpload(ctx context.Context, rekorClient *client.Rekor, pe models.ProposedEntry) (*models.LogEntryAnon, error) {
	params := entries.NewCreateLogEntryParamsWithContext(ctx)
	params.SetProposedEntry(pe)
	resp, err := rekorClient.Entries.CreateLogEntry(params)
	if err != nil {
		// If the entry already exists, we get a specific error.
		// Here, we display the proof and succeed.
		var existsErr *entries.CreateLogEntryConflict
		if errors.As(err, &existsErr) {
			fmt.Println("Signature already exists. Displaying proof")
			uriSplit := strings.Split(existsErr.Location.String(), "/")
			uuid := uriSplit[len(uriSplit)-1]
			e, err := GetTlogEntry(ctx, rekorClient, uuid)
			if err != nil {
				return nil, err
			}
			return e, VerifyTLogEntry(ctx, rekorClient, e)
		}
		return nil, err
	}
	// UUID is at the end of location
	for _, p := range resp.Payload {
		return &p, nil
	}
	return nil, errors.New("bad response from server")
}

func intotoEntry(signature, pubKey []byte) intoto_v001.V001Entry {
	pub := strfmt.Base64(pubKey)
	return intoto_v001.V001Entry{
		IntotoObj: models.IntotoV001Schema{
			Content: &models.IntotoV001SchemaContent{
				Envelope: string(signature),
			},
			PublicKey: &pub,
		},
	}
}

func rekorEntry(payload, signature, pubKey []byte) hashedrekord_v001.V001Entry {
	// TODO: Signatures created on a digest using a hash algorithm other than SHA256 will fail
	// upload right now. Plumb information on the hash algorithm used when signing from the
	// SignerVerifier to use for the HashedRekordObj.Data.Hash.Algorithm.
	h := sha256.Sum256(payload)
	return hashedrekord_v001.V001Entry{
		HashedRekordObj: models.HashedrekordV001Schema{
			Data: &models.HashedrekordV001SchemaData{
				Hash: &models.HashedrekordV001SchemaDataHash{
					Algorithm: swag.String(models.HashedrekordV001SchemaDataHashAlgorithmSha256),
					Value:     swag.String(hex.EncodeToString(h[:])),
				},
			},
			Signature: &models.HashedrekordV001SchemaSignature{
				Content: strfmt.Base64(signature),
				PublicKey: &models.HashedrekordV001SchemaSignaturePublicKey{
					Content: strfmt.Base64(pubKey),
				},
			},
		},
	}
}

func ComputeLeafHash(e *models.LogEntryAnon) ([]byte, error) {
	entryBytes, err := base64.StdEncoding.DecodeString(e.Body.(string))
	if err != nil {
		return nil, err
	}
	return rfc6962.DefaultHasher.HashLeaf(entryBytes), nil
}

func verifyUUID(uuid string, e models.LogEntryAnon) error {
	entryUUID, _ := hex.DecodeString(uuid)

	// Verify leaf hash matches hash of the entry body.
	computedLeafHash, err := ComputeLeafHash(&e)
	if err != nil {
		return err
	}
	if !bytes.Equal(computedLeafHash, entryUUID) {
		return fmt.Errorf("computed leaf hash did not match entry UUID")
	}
	return nil
}

func GetTlogEntry(ctx context.Context, rekorClient *client.Rekor, uuid string) (*models.LogEntryAnon, error) {
	params := entries.NewGetLogEntryByUUIDParamsWithContext(ctx)
	params.SetEntryUUID(uuid)
	resp, err := rekorClient.Entries.GetLogEntryByUUID(params)
	if err != nil {
		return nil, err
	}
	for k, e := range resp.Payload {
		// Check that body hash matches UUID
		if k != uuid {
			return nil, fmt.Errorf("unexpected entry returned from rekor server")
		}
		if err := verifyUUID(k, e); err != nil {
			return nil, err
		}
		return &e, nil
	}
	return nil, errors.New("empty response")
}

func proposedEntry(b64Sig string, payload, pubKey []byte) ([]models.ProposedEntry, error) {
	var proposedEntry []models.ProposedEntry
	signature, err := base64.StdEncoding.DecodeString(b64Sig)
	if err != nil {
		return nil, fmt.Errorf("decoding base64 signature: %w", err)
	}

	// The fact that there's no signature (or empty rather), implies
	// that this is an Attestation that we're verifying.
	if len(signature) == 0 {
		te := intotoEntry(payload, pubKey)
		entry := &models.Intoto{
			APIVersion: swag.String(te.APIVersion()),
			Spec:       te.IntotoObj,
		}
		proposedEntry = []models.ProposedEntry{entry}
	} else {
		re := rekorEntry(payload, signature, pubKey)
		entry := &models.Hashedrekord{
			APIVersion: swag.String(re.APIVersion()),
			Spec:       re.HashedRekordObj,
		}
		proposedEntry = []models.ProposedEntry{entry}
	}
	return proposedEntry, nil
}

func FindTlogEntry(ctx context.Context, rekorClient *client.Rekor, b64Sig string, payload, pubKey []byte) (entry *models.LogEntryAnon, err error) {
	searchParams := entries.NewSearchLogQueryParamsWithContext(ctx)
	searchLogQuery := models.SearchLogQuery{}
	proposedEntry, err := proposedEntry(b64Sig, payload, pubKey)
	if err != nil {
		return nil, err
	}

	searchLogQuery.SetEntries(proposedEntry)

	searchParams.SetEntry(&searchLogQuery)
	resp, err := rekorClient.Entries.SearchLogQuery(searchParams)
	if err != nil {
		return nil, fmt.Errorf("searching log query: %w", err)
	}
	if len(resp.Payload) == 0 {
		return nil, errors.New("signature not found in transparency log")
	} else if len(resp.Payload) > 1 {
		return nil, errors.New("multiple entries returned; this should not happen")
	}
	logEntry := resp.Payload[0]
	if len(logEntry) != 1 {
		return nil, errors.New("UUID value can not be extracted")
	}

	var tlogEntry models.LogEntryAnon
	for k, e := range logEntry {
		// Check body hash matches uuid
		if err := verifyUUID(k, e); err != nil {
			return nil, err
		}
		tlogEntry = e
	}
	return &tlogEntry, nil
}

func FindTLogEntriesByPayload(ctx context.Context, rekorClient *client.Rekor, payload []byte) (uuids []string, err error) {
	params := index.NewSearchIndexParamsWithContext(ctx)
	params.Query = &models.SearchIndex{}

	h := sha256.New()
	h.Write(payload)
	params.Query.Hash = fmt.Sprintf("sha256:%s", strings.ToLower(hex.EncodeToString(h.Sum(nil))))

	searchIndex, err := rekorClient.Index.SearchIndex(params)
	if err != nil {
		return nil, err
	}
	return searchIndex.GetPayload(), nil
}

// VerityTLogEntry verifies a TLog entry. If the Env variable
// SIGSTORE_TRUST_REKOR_API_PUBLIC_KEY is specified, fetches the Rekor public
// key from the Rekor server using the provided rekorClient.
func VerifyTLogEntry(ctx context.Context, rekorClient *client.Rekor, e *models.LogEntryAnon) error {
	if e.Verification == nil || e.Verification.InclusionProof == nil {
		return errors.New("inclusion proof not provided")
	}

	hashes := [][]byte{}
	for _, h := range e.Verification.InclusionProof.Hashes {
		hb, _ := hex.DecodeString(h)
		hashes = append(hashes, hb)
	}

	rootHash, _ := hex.DecodeString(*e.Verification.InclusionProof.RootHash)
	entryBytes, err := base64.StdEncoding.DecodeString(e.Body.(string))
	if err != nil {
		return err
	}
	leafHash := rfc6962.DefaultHasher.HashLeaf(entryBytes)

	// Verify the inclusion proof.
	if err := proof.VerifyInclusion(rfc6962.DefaultHasher, uint64(*e.Verification.InclusionProof.LogIndex), uint64(*e.Verification.InclusionProof.TreeSize),
		leafHash, hashes, rootHash); err != nil {
		return fmt.Errorf("verifying inclusion proof: %w", err)
	}

	// Verify rekor's signature over the SET.
	payload := bundle.RekorPayload{
		Body:           e.Body,
		IntegratedTime: *e.IntegratedTime,
		LogIndex:       *e.LogIndex,
		LogID:          *e.LogID,
	}

	// If we've been told to fetch the Public Key from Rekor, fetch it here
	// first before using the TUF code below.
	rekorPubKeys := make(map[string]RekorPubKey)
	addRekorPublic := os.Getenv(addRekorPublicKeyFromRekor)
	if addRekorPublic != "" {
		pubOK, err := rekorClient.Pubkey.GetPublicKey(nil)
		if err != nil {
			return fmt.Errorf("unable to fetch rekor public key from rekor: %w", err)
		}
		pubFromAPI, err := PemToECDSAKey([]byte(pubOK.Payload))
		if err != nil {
			return fmt.Errorf("error converting rekor PEM public key from rekor to ECDSAKey: %w", err)
		}
		keyID, err := getLogID(pubFromAPI)
		if err != nil {
			return fmt.Errorf("error generating log ID: %w", err)
		}
		rekorPubKeys[keyID] = RekorPubKey{PubKey: pubFromAPI, Status: tuf.Active}
	}

	rekorPubKeysTuf, err := GetRekorPubs(ctx)
	if err != nil {
		if len(rekorPubKeys) == 0 {
			return fmt.Errorf("unable to fetch Rekor public keys from TUF repository, and not trusting the Rekor API for fetching public keys: %w", err)
		}
		fmt.Fprintf(os.Stderr, "**Warning** Failed to fetch Rekor public keys from TUF, using the public key from Rekor API because %s was specified", addRekorPublicKeyFromRekor)
	}

	for k, v := range rekorPubKeysTuf {
		rekorPubKeys[k] = v
	}
	pubKey, ok := rekorPubKeys[payload.LogID]
	if !ok {
		return errors.New("rekor log public key not found for payload")
	}
	err = VerifySET(payload, []byte(e.Verification.SignedEntryTimestamp), pubKey.PubKey)
	if err != nil {
		return fmt.Errorf("verifying signedEntryTimestamp: %w", err)
	}
	if pubKey.Status != tuf.Active {
		fmt.Fprintf(os.Stderr, "**Info** Successfully verified Rekor entry using an expired verification key\n")
	}
	return nil
}
