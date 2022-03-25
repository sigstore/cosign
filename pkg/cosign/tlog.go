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
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/google/trillian/merkle/logverifier"
	"github.com/google/trillian/merkle/rfc6962"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/pkg/cosign/bundle"
	"github.com/sigstore/cosign/pkg/cosign/tuf"
	"github.com/sigstore/rekor/pkg/generated/client/index"

	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
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

// GetRekorPubs retrieves trusted Rekor public keys from the embedded or cached
// TUF root. If expired, makes a network call to retrieve the updated targets.
func GetRekorPubs(ctx context.Context) ([]RekorPubKey, error) {
	tufClient, err := tuf.NewFromEnv(ctx)
	if err != nil {
		return nil, err
	}
	defer tufClient.Close()
	targets, err := tufClient.GetTargetsByMeta(tuf.Rekor, []string{rekorTargetStr})
	if err != nil {
		return nil, err
	}
	publicKeys := make([]RekorPubKey, 0, len(targets))
	altRekorPub := os.Getenv(altRekorPublicKey)
	if altRekorPub != "" {
		fmt.Fprintf(os.Stderr, "**Warning** Using a non-standard public key for Rekor: %s\n", altRekorPub)
		raw, err := os.ReadFile(altRekorPub)
		if err != nil {
			return nil, errors.Wrap(err, "error reading alternate Rekor public key file")
		}
		extra, err := PemToECDSAKey(raw)
		if err != nil {
			return nil, errors.Wrap(err, "error converting PEM to ECDSAKey")
		}
		publicKeys = append(publicKeys, RekorPubKey{PubKey: extra, Status: tuf.Active})
	} else {
		for _, t := range targets {
			rekorPubKey, err := PemToECDSAKey(t.Target)
			if err != nil {
				return nil, errors.Wrap(err, "pem to ecdsa")
			}
			publicKeys = append(publicKeys, RekorPubKey{PubKey: rekorPubKey, Status: t.Status})
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
			return VerifyTLogEntry(ctx, rekorClient, e, uuid)
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

func GetTlogEntry(ctx context.Context, rekorClient *client.Rekor, uuid string) (*models.LogEntryAnon, error) {
	params := entries.NewGetLogEntryByUUIDParamsWithContext(ctx)
	params.SetEntryUUID(uuid)
	resp, err := rekorClient.Entries.GetLogEntryByUUID(params)
	if err != nil {
		return nil, err
	}
	for _, e := range resp.Payload {
		return &e, nil
	}
	return nil, errors.New("empty response")
}

func proposedEntry(b64Sig string, payload, pubKey []byte) ([]models.ProposedEntry, error) {
	var proposedEntry []models.ProposedEntry
	signature, err := base64.StdEncoding.DecodeString(b64Sig)
	if err != nil {
		return nil, errors.Wrap(err, "decoding base64 signature")
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

func FindTlogEntry(ctx context.Context, rekorClient *client.Rekor, b64Sig string, payload, pubKey []byte) (uuid string, tlogEntry *models.LogEntryAnon, index int64, err error) {
	searchParams := entries.NewSearchLogQueryParamsWithContext(ctx)
	searchLogQuery := models.SearchLogQuery{}
	proposedEntry, err := proposedEntry(b64Sig, payload, pubKey)
	if err != nil {
		return "", nil, 0, err
	}

	searchLogQuery.SetEntries(proposedEntry)

	searchParams.SetEntry(&searchLogQuery)
	resp, err := rekorClient.Entries.SearchLogQuery(searchParams)
	if err != nil {
		return "", nil, 0, errors.Wrap(err, "searching log query")
	}
	if len(resp.Payload) == 0 {
		return "", nil, 0, errors.New("signature not found in transparency log")
	} else if len(resp.Payload) > 1 {
		return "", nil, 0, errors.New("multiple entries returned; this should not happen")
	}
	logEntry := resp.Payload[0]
	if len(logEntry) != 1 {
		return "", nil, 0, errors.New("UUID value can not be extracted")
	}

	for k, e := range logEntry {
		uuid = k
		tlogEntry = &e
	}
	return uuid, tlogEntry, *tlogEntry.Verification.InclusionProof.LogIndex, nil
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

func VerifyTLogEntry(ctx context.Context, rekorClient *client.Rekor, e *models.LogEntryAnon, uuid string) (*models.LogEntryAnon, error) {
	if e.Verification == nil || e.Verification.InclusionProof == nil {
		return nil, errors.New("inclusion proof not provided")
	}

	hashes := [][]byte{}
	for _, h := range e.Verification.InclusionProof.Hashes {
		hb, _ := hex.DecodeString(h)
		hashes = append(hashes, hb)
	}

	rootHash, _ := hex.DecodeString(*e.Verification.InclusionProof.RootHash)
	leafHash, _ := hex.DecodeString(uuid)

	// Verify leaf hash matches hash of the entry body.
	entryBytes, err := base64.StdEncoding.DecodeString(e.Body.(string))
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(rfc6962.DefaultHasher.HashLeaf(entryBytes), leafHash) {
		return nil, fmt.Errorf("computed leaf hash did not match entry UUID")
	}

	v := logverifier.New(rfc6962.DefaultHasher)
	if err := v.VerifyInclusionProof(*e.Verification.InclusionProof.LogIndex, *e.Verification.InclusionProof.TreeSize, hashes, rootHash, leafHash); err != nil {
		return nil, errors.Wrap(err, "verifying inclusion proof")
	}

	// Verify rekor's signature over the SET.
	payload := bundle.RekorPayload{
		Body:           e.Body,
		IntegratedTime: *e.IntegratedTime,
		LogIndex:       *e.LogIndex,
		LogID:          *e.LogID,
	}

	rekorPubKeys, err := GetRekorPubs(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "unable to fetch Rekor public keys from TUF repository")
	}

	addRekorPublic := os.Getenv(addRekorPublicKeyFromRekor)
	if addRekorPublic != "" {
		pubOK, err := rekorClient.Pubkey.GetPublicKey(nil)
		if err != nil {
			return nil, errors.Wrap(err, "unable to fetch rekor public key from rekor")
		}
		pubFromAPI, err := PemToECDSAKey([]byte(pubOK.Payload))
		if err != nil {
			return nil, errors.Wrap(err, "error converting rekor PEM public key from rekor to ECDSAKey")
		}
		rekorPubKeys = append(rekorPubKeys, RekorPubKey{PubKey: pubFromAPI, Status: tuf.Active})
	}

	var entryVerError error
	for _, pubKey := range rekorPubKeys {
		entryVerError = VerifySET(payload, []byte(e.Verification.SignedEntryTimestamp), pubKey.PubKey)
		// Return once the SET is verified successfully.
		if entryVerError == nil {
			if pubKey.Status != tuf.Active {
				fmt.Fprintf(os.Stderr, "**Info** Successfully verified Rekor entry using an expired verification key\n")
			}
			return e, nil
		}
	}
	return nil, errors.Wrap(entryVerError, "verifying signedEntryTimestamp")
}
