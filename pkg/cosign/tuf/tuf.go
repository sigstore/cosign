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

package tuf

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/pkg/cosign"
	cremote "github.com/sigstore/cosign/pkg/cosign/remote"
	"github.com/sigstore/sigstore/pkg/signature"
	cjson "github.com/tent/canonical-json-go"
	"github.com/theupdateframework/go-tuf"
	"github.com/theupdateframework/go-tuf/data"
	"github.com/theupdateframework/go-tuf/util"
	"github.com/theupdateframework/go-tuf/verify"
)

var StagedMetadataFile = "/staged-well-known.tuf"
var MetadataFile = "/well-known.tuf"

var TopLevelManifests = []string{
	"root.json",
	"targets.json",
	"snapshot.json",
	"timestamp.json",
}

type RepoOpts struct {
	Keys       map[string][]string           // map from role.json to public keys
	RemoveKeys map[string][]string           // mape from role.json to public keys
	Thresholds map[string]int                // map from role.json to thresholds
	Signers    map[string][]signature.Signer // map from role.json to list of signer private key references
	Targets    []string                      // targets to add
}

func writeMetaFromStore(store tuf.LocalStore) ([]byte, error) {
	meta, err := store.GetMeta()
	if err != nil {
		return nil, err
	}

	metaJSON, err := cjson.Marshal(meta)
	if err != nil {
		return nil, err
	}

	return metaJSON, nil
}

func GetSignedMeta(store tuf.LocalStore, name string) (*data.Signed, error) {
	meta, err := store.GetMeta()
	if err != nil {
		return nil, err
	}
	signedJSON, ok := meta[name]
	if !ok {
		return nil, fmt.Errorf("missing metadata %s", name)
	}
	s := &data.Signed{}
	if err := json.Unmarshal(signedJSON, s); err != nil {
		return nil, err
	}
	return s, nil
}

func getPublicKeyFromRef(ctx context.Context, ref string) (*data.Key, error) {
	pubKey, err := cosign.LoadPublicKey(ctx, ref)
	if err != nil {
		return nil, err
	}
	pub, err := pubKey.PublicKey(ctx)
	if err != nil {
		return nil, err
	}
	// RSA is not supported in go-tuf
	return tufKeyFromPublic(pub)
}

func GetRootFromStore(store *tuf.LocalStore) (*data.Root, error) {
	s, err := GetSignedMeta(*store, "root.json")
	if err != nil {
		return nil, err
	}
	root := &data.Root{}
	if err := json.Unmarshal(s.Signed, root); err != nil {
		return nil, err
	}
	return root, nil
}

func GetTargetsFromStore(store *tuf.LocalStore) (*data.Targets, error) {
	s, err := GetSignedMeta(*store, "targets.json")
	if err != nil {
		return nil, err
	}
	targets := &data.Targets{}
	if err := json.Unmarshal(s.Signed, targets); err != nil {
		return nil, err
	}
	return targets, nil
}

func UpdateRepo(ctx context.Context, store *tuf.LocalStore, opts RepoOpts, staged bool) (bool, error) {
	// Increment versions if files changed and we were not already staged.
	// Updates root.json. Returns true if repo complete.
	repo, err := tuf.NewRepo(*store)
	if err != nil {
		return false, err
	}

	root, err := GetRootFromStore(store)
	if err != nil {
		return false, err
	}

	changed := false
	for _, role := range TopLevelManifests {
		rolename := strings.TrimSuffix(role, ".json")

		// Add and remove keys
		if keys, ok := opts.RemoveKeys[role]; ok {
			for _, keyRef := range keys {
				tufKey, err := getPublicKeyFromRef(ctx, keyRef)
				if err != nil {
					return false, err
				}
				// Should we be careful of all key IDs?
				changed = true
				if err := repo.RevokeKey(rolename, tufKey.IDs()[0]); err != nil {
					return false, err
				}
			}
		}

		if keys, ok := opts.Keys[role]; ok {
			for _, keyRef := range keys {
				tufKey, err := getPublicKeyFromRef(ctx, keyRef)
				if err != nil {
					return false, err
				}
				changed = true
				root.AddKey(tufKey)
				role := root.Roles[rolename]
				role.AddKeyIDs(tufKey.IDs())
			}
			// TODO: If there are no keys added, generate one and write to file.
		}

		// Update thresholds
		if threshold, ok := opts.Thresholds[role]; ok {
			if threshold != 0 {
				root.Roles[rolename].Threshold = threshold
				changed = true
			}
		}
	}

	if changed {
		if !staged {
			root.Version++
		}
		// This will remove any signatures, since the metadata has changed
		if err := setMeta(*store, "root.json", root); err != nil {
			return false, err
		}
	}

	//  TODO: add targets. if added and not staged, increment targets and snapshot versions.
	if err := addTargets(store, opts.Targets); err != nil {
		return false, err
	}

	// Update hashes in snapshot and timestamp to correspond to the updated root.
	if err := signAndUpdateMetaHashes(ctx, store, opts.Signers); err != nil {
		fmt.Fprintf(os.Stderr, "verification error: %s\n", err)
		return false, nil
	}

	// Do a full verification and publish any staged meta
	repo, err = tuf.NewRepo(*store)
	if err != nil {
		return false, err
	}

	err = repo.Commit()
	verified := err == nil
	if !verified {
		fmt.Fprintf(os.Stderr, "metadata verification failed: %s\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "metadata verified!\n")
	}

	return verified, nil
}

func SignMeta(ctx context.Context, store tuf.LocalStore, name string, signer signature.Signer) error {
	pubKey, err := signer.PublicKey(ctx)
	if err != nil {
		return err
	}
	key, err := tufKeyFromPublic(pubKey)
	if err != nil {
		return err
	}

	s, err := GetSignedMeta(store, name)
	if err != nil {
		return err
	}

	// Sign payload
	sig, _, err := signer.Sign(ctx, s.Signed)
	if err != nil {
		return err
	}

	if s.Signatures == nil {
		s.Signatures = make([]data.Signature, 0, 1)
	}
	for _, id := range key.IDs() {
		s.Signatures = append(s.Signatures, data.Signature{
			KeyID:     id,
			Signature: sig,
		})
	}

	return setSignedMeta(store, name, s)
}

func tufKeyFromPublic(pub crypto.PublicKey) (*data.Key, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return &data.Key{
			Type:       data.KeyTypeECDSA_SHA2_P256,
			Scheme:     data.KeySchemeECDSA_SHA2_P256,
			Algorithms: data.KeyAlgorithms,
			Value:      data.KeyValue{Public: elliptic.Marshal(k.Curve, k.X, k.Y)},
		}, nil
	case *ed25519.PublicKey:
		return &data.Key{
			Type:       data.KeyTypeEd25519,
			Scheme:     data.KeySchemeEd25519,
			Algorithms: data.KeyAlgorithms,
			Value:      data.KeyValue{Public: data.HexBytes(*k)},
		}, nil
	default:
		return nil, errors.New("unsupported public key type")
	}
}

func jsonMarshal(v interface{}) ([]byte, error) {
	signed, err := cjson.Marshal(v)
	if err != nil {
		return nil, err
	}
	return signed, nil
}

func setMeta(store tuf.LocalStore, role string, meta interface{}) error {
	signed, err := jsonMarshal(meta)
	if err != nil {
		return err
	}

	return setSignedMeta(store, role, &data.Signed{Signed: signed})
}

func setSignedMeta(store tuf.LocalStore, role string, s *data.Signed) error {
	b, err := jsonMarshal(s)
	if err != nil {
		return err
	}
	return store.SetMeta(role, b)
}

func CreateDb(store *tuf.LocalStore) (*verify.DB, error) {
	db := verify.NewDB()
	root, err := GetRootFromStore(store)
	if err != nil {
		return nil, err
	}
	for id, k := range root.Keys {
		if err := db.AddKey(id, k); err != nil {
			// ignore ErrWrongID errors by TAP-12
			if _, ok := err.(verify.ErrWrongID); !ok {
				return nil, err
			}
		}
	}
	for name, role := range root.Roles {
		if err := db.AddRole(name, role); err != nil {
			return nil, err
		}
	}
	return db, nil
}

// Upload Meta to registry
func UploadStoreToRegistry(store tuf.LocalStore, repo string, verified bool) error {
	var refString string
	if verified {
		refString = repo + MetadataFile
	} else {
		refString = repo + StagedMetadataFile
	}
	ref, err := name.ParseReference(refString)
	if err != nil {
		return err
	}

	// Construct metadata JSON from store
	metaJSON, err := writeMetaFromStore(store)
	if err != nil {
		return err
	}

	// Write metadata JSON
	tmpfile, err := ioutil.TempFile("", "metadata")
	if err != nil {
		return err
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write(metaJSON); err != nil {
		return err
	}

	// Upload
	files := []cremote.File{{Path: tmpfile.Name()}}

	dgster, err := cremote.UploadFiles(ref, files)
	if err != nil {
		return err
	}

	dgst, err := dgster.Digest()
	if err != nil {
		return err
	}
	dgstAddr := fmt.Sprintf("%s@%s", ref.Context().Name(), dgst.String())

	if verified {
		fmt.Fprintf(os.Stderr, "Uploaded TUF metadata to %s\n\n", dgstAddr)

		fmt.Printf("Distribute the following root.json:\n")
		meta, err := store.GetMeta()
		if err != nil {
			return err
		}
		rootJSON := meta["root.json"]
		j, err := json.Marshal(&rootJSON)
		if err != nil {
			panic(err)
		}
		fmt.Println(string(j))
	}
	return nil
}

// Get Meta from registry. Return store, true if staged metadata, or error.
func GetStoreFromRegistry(repo string) (tuf.LocalStore, bool, error) {
	// Get the well-known.tuf blob from the repository
	ref, err := name.ParseReference(repo + MetadataFile)
	if err != nil {
		return nil, false, err
	}

	var storeBlob []byte
	staged := false
	storeBlob, err = cremote.GetFile(ref)
	if err != nil {
		// Try getting staged meta.
		ref, err := name.ParseReference(repo + StagedMetadataFile)
		if err != nil {
			return nil, false, err
		}

		storeBlob, err = cremote.GetFile(ref)
		if err != nil {
			return nil, false, err
		}
		staged = true
	}

	var rawMeta map[string]json.RawMessage
	if err := json.Unmarshal(storeBlob, &rawMeta); err != nil {
		return nil, false, err
	}

	// TODO: We should probably do some verification on read,
	// although this happens on write.
	store := tuf.MemoryStore(rawMeta, nil)

	return store, staged, nil
}

// Generate an new in-memory store from an OCI repository
func NewStore() (*tuf.LocalStore, error) {
	store := tuf.MemoryStore(nil, nil)

	repo, err := tuf.NewRepo(store)
	if err != nil {
		return nil, err
	}

	if err := repo.Init(false); err != nil {
		return nil, err
	}

	root, err := GetRootFromStore(&store)
	if err != nil {
		return nil, err
	}

	// Add blank roles with default thresholds
	for _, role := range TopLevelManifests {
		rolename := strings.TrimSuffix(role, ".json")

		if _, ok := root.Roles[rolename]; !ok {
			role := &data.Role{KeyIDs: []string{}, Threshold: 1}
			root.Roles[rolename] = role
		}
	}
	if err := setMeta(store, "root.json", root); err != nil {
		return nil, err
	}

	// Add empty targets, snapshot, and timestamp
	// Add targets.
	if err := repo.AddTargets(nil, nil); err != nil {
		return nil, fmt.Errorf("error adding targets %w", err)
	}

	// Create snapshot.json
	if err := updateSnapshot(store, false); err != nil {
		return nil, err
	}

	// Create timestamp.json
	if err := updateTimestamp(store, false); err != nil {
		return nil, err
	}

	return &store, nil
}

func signAndUpdateMetaHashes(ctx context.Context, store *tuf.LocalStore, signers map[string][]signature.Signer) error {
	db, err := CreateDb(store)
	if err != nil {
		return fmt.Errorf("error creating verification database: %w", err)
	}

	// sign root and targets
	changed := false // if we need to recalculate hashes in snapshot or not
	for _, role := range []string{"root.json", "targets.json"} {
		for _, signer := range signers[role] {
			if err := SignMeta(ctx, *store, role, signer); err != nil {
				return err
			}
			changed = true
		}
	}

	for _, manifest := range []string{"root", "targets"} {
		s, err := GetSignedMeta(*store, manifest+".json")
		if err != nil {
			return err
		}
		if err := db.Verify(s, manifest, 0); err != nil {
			return fmt.Errorf("error verifying signatures for %s", manifest)
		}
	}
	// update snapshot hashes if root or targets updated
	if changed {
		// increment version if we are sign-and-snapshotting
		version := len(signers["snapshot.json"]) > 0
		if err := updateSnapshot(*store, version); err != nil {
			return err
		}
	}
	// sign snapshot
	for _, signer := range signers["snapshot.json"] {
		if err := SignMeta(ctx, *store, "snapshot.json", signer); err != nil {
			return err
		}
		changed = true
	}

	// timestamp
	// Check that snapshot is signed
	s, err := GetSignedMeta(*store, "snapshot.json")
	if err != nil {
		return err
	}
	if err := db.Verify(s, "snapshot", 0); err != nil {
		return errors.New("error verifying signatures for snapshot")
	}

	signTimestamp := len(signers["timestamp.json"]) > 0
	if changed || signTimestamp {
		// increment version if we are timestamping
		if err := updateTimestamp(*store, signTimestamp); err != nil {
			return err
		}
	}

	for _, signer := range signers["timestamp.json"] {
		if err := SignMeta(ctx, *store, "timestamp.json", signer); err != nil {
			return err
		}
	}

	return nil
}

func updateSnapshot(store tuf.LocalStore, version bool) error {
	snapshot := &data.Snapshot{}

	s, err := GetSignedMeta(store, "snapshot.json")
	if err != nil {
		snapshot = data.NewSnapshot()
	} else if err := json.Unmarshal(s.Signed, snapshot); err != nil {
		return err
	}

	meta, err := store.GetMeta()
	if err != nil {
		return err
	}

	for _, name := range []string{"root.json", "targets.json"} {
		b := meta[name]
		snapshot.Meta[name], err = util.GenerateSnapshotFileMeta(bytes.NewReader(b))
		if err != nil {
			return err
		}
	}

	if version {
		snapshot.Version++
	}

	return setMeta(store, "snapshot.json", snapshot)
}

func updateTimestamp(store tuf.LocalStore, version bool) error {
	timestamp := &data.Timestamp{}

	s, err := GetSignedMeta(store, "timestamp.json")
	if err != nil {
		timestamp = data.NewTimestamp()
	} else if err := json.Unmarshal(s.Signed, timestamp); err != nil {
		return err
	}

	meta, err := store.GetMeta()
	if err != nil {
		return err
	}
	b, ok := meta["snapshot.json"]
	if !ok {
		return errors.New("missing metadata: snapshot.json")
	}
	timestamp.Meta["snapshot.json"], err = util.GenerateTimestampFileMeta(bytes.NewReader(b))
	if err != nil {
		return err
	}

	if version {
		timestamp.Version++
	}

	return setMeta(store, "timestamp.json", timestamp)
}

func addTargets(store *tuf.LocalStore, images []string) error {
	t, err := GetTargetsFromStore(store)
	if err != nil {
		return err
	}

	changed := false
	for _, imageRef := range images {
		meta, err := GenerateTargetMeta(imageRef)
		if err != nil {
			return err
		}
		t.Targets[imageRef] = *meta
		changed = true
	}

	// TODO: Don't know why the version is already incremented to 1 after the root. Maybe indicated targets key change?
	// Does this only change if the targets changed (or also if the targets key changes)
	if changed {
		t.Version++
		// Only do this if there were images
		return setMeta(*store, "targets.json", t)
	}

	return nil
}

func GenerateTargetMeta(imageRef string) (*data.TargetFileMeta, error) {
	ref, err := name.ParseReference(imageRef, name.WeakValidation)
	if err != nil {
		return nil, err
	}
	img, err := remote.Image(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return nil, err
	}

	hash, err := img.Digest()
	if err != nil {
		return nil, err
	}
	n, err := img.Size()
	if err != nil {
		return nil, err
	}

	dgst, err := hex.DecodeString(hash.Hex)
	if err != nil {
		return nil, err
	}

	return &data.TargetFileMeta{FileMeta: data.FileMeta{
		Length: n,
		Hashes: map[string]data.HexBytes{
			hash.Algorithm: dgst}}}, nil
}

func Verify(root []byte, image string) error {
	// Add trusted root keys
	s := &data.Signed{}
	if err := json.Unmarshal(root, s); err != nil {
		return err
	}
	trusted := &data.Root{}
	if err := json.Unmarshal(s.Signed, trusted); err != nil {
		return err
	}

	db := verify.NewDB()
	rootKeyIDs := make([]string, 0, len(trusted.Keys))
	for id, k := range trusted.Keys {
		if err := db.AddKey(id, k); err != nil {
			// ignore ErrWrongID errors by TAP-12
			if _, ok := err.(verify.ErrWrongID); !ok {
				return err
			}
		}
		rootKeyIDs = append(rootKeyIDs, id)
	}

	role := &data.Role{Threshold: trusted.Roles["root"].Threshold, KeyIDs: rootKeyIDs}
	if err := db.AddRole("root", role); err != nil {
		return err
	}

	// Verify the root on the registry is valid TODO
	ref, err := name.ParseReference(image)
	if err != nil {
		return err
	}
	repo := ref.Context().Name()
	fmt.Fprintf(os.Stderr, "repository %s\n", repo)

	store, _, err := GetStoreFromRegistry(repo)
	if err != nil {
		return err
	}

	// Now that we trust the current meta, save all roles to the db.
	db, err = CreateDb(&store)
	if err != nil {
		return err
	}

	// Verify the metadata on the registry
	for _, manifest := range []string{"root", "targets"} {
		s, err := GetSignedMeta(store, manifest+".json")
		if err != nil {
			return err
		}
		if err := db.Verify(s, manifest, 0); err != nil {
			return fmt.Errorf("error verifying signatures for %s: %w", manifest, err)
		}
	}

	// Check snapshot and signatures in snapshot
	meta, err := store.GetMeta()
	if err != nil {
		return err
	}

	snapshot := &data.Snapshot{}
	snapshotS, err := GetSignedMeta(store, "snapshot.json")
	if err != nil {
		return err
	}
	if err := json.Unmarshal(snapshotS.Signed, snapshot); err != nil {
		return err
	}

	for _, name := range []string{"root.json", "targets.json"} {
		b := meta[name]
		newMeta, err := util.GenerateSnapshotFileMeta(bytes.NewReader(b))
		if err != nil {
			return err
		}
		if err := util.SnapshotFileMetaEqual(newMeta, snapshot.Meta[name]); err != nil {
			return err
		}
	}

	if err := db.Verify(snapshotS, "snapshot", 0); err != nil {
		return fmt.Errorf("error verifying signatures for snapshot: %w", err)
	}

	// Check timestamp meta and signatures in timestamp
	timestamp := &data.Timestamp{}
	sTimestamp, err := GetSignedMeta(store, "timestamp.json")
	if err != nil {
		return err
	}
	if err := json.Unmarshal(sTimestamp.Signed, timestamp); err != nil {
		return err
	}

	b, ok := meta["snapshot.json"]
	if !ok {
		return errors.New("missing metadata: snapshot.json")
	}
	prev, err := util.GenerateTimestampFileMeta(bytes.NewReader(b))
	if err != nil {
		return err
	}
	if err := util.TimestampFileMetaEqual(prev, timestamp.Meta["snapshot.json"]); err != nil {
		return err
	}

	if err := db.Verify(sTimestamp, "timestamp", 0); err != nil {
		return fmt.Errorf("error verifying signatures for timestamp: %w", err)
	}

	// Now that we have valid metadata, check the image sha in the targets file
	t, err := GetTargetsFromStore(&store)
	if err != nil {
		return err
	}
	expectedMeta, err := GenerateTargetMeta(image)
	if err != nil {
		return err
	}
	if err := util.TargetFileMetaEqual(*expectedMeta, t.Targets[image]); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Target hashes match\n")

	fmt.Fprintf(os.Stderr, "Verified image\n")
	return nil
}
