//
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

// Contains root policy definitions.
// Eventually, this will move this to go-tuf definitions.

package tuf

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"

	cjson "github.com/tent/canonical-json-go"
)

type Signed struct {
	Signed     json.RawMessage `json:"signed"`
	Signatures []Signature     `json:"signatures"`
}

type Signature struct {
	KeyID     string `json:"keyid"`
	Signature string `json:"sig"`
	Cert      string `json:"cert,omitempty"`
}

type Key struct {
	Type       string          `json:"keytype"`
	Scheme     string          `json:"scheme"`
	Algorithms []string        `json:"keyid_hash_algorithms,omitempty"`
	Value      json.RawMessage `json:"keyval"`

	id     string
	idOnce sync.Once
}

func (k *Key) ID() string {
	k.idOnce.Do(func() {
		data, _ := cjson.Marshal(k)
		digest := sha256.Sum256(data)
		k.id = hex.EncodeToString(digest[:])
	})
	return k.id
}

func (k *Key) ContainsID(id string) bool {
	return id == k.ID()
}

type Root struct {
	Type        string           `json:"_type"`
	SpecVersion string           `json:"spec_version"`
	Version     int              `json:"version"`
	Expires     time.Time        `json:"expires"`
	Keys        map[string]*Key  `json:"keys"`
	Roles       map[string]*Role `json:"roles"`
	Namespace   string           `json:"namespace"`

	ConsistentSnapshot bool `json:"consistent_snapshot"`
}

func DefaultExpires(role string) time.Time {
	// Default expires in 3 months
	return time.Now().AddDate(0, 3, 0).UTC().Round(time.Second)
}

func NewRoot() *Root {
	return &Root{
		Type:               "root",
		SpecVersion:        "1.0",
		Version:            1,
		Expires:            DefaultExpires("root"),
		Keys:               make(map[string]*Key),
		Roles:              make(map[string]*Role),
		ConsistentSnapshot: true,
	}
}

func (r *Root) AddKey(key *Key) bool {
	changed := false
	if _, ok := r.Keys[key.ID()]; !ok {
		changed = true
		r.Keys[key.ID()] = key
	}

	return changed
}

type Role struct {
	KeyIDs    []string `json:"keyids"`
	Threshold int      `json:"threshold"`
}

func (r *Role) AddKeysWithThreshold(keys []*Key, threshold int) bool {
	roleIDs := make(map[string]struct{})
	for _, id := range r.KeyIDs {
		roleIDs[id] = struct{}{}
	}
	changed := false
	for _, key := range keys {
		if _, ok := roleIDs[key.ID()]; !ok {
			changed = true
			r.KeyIDs = append(r.KeyIDs, key.ID())
		}
	}
	r.Threshold = threshold
	return changed
}

func (r *Root) Marshal() (*Signed, error) {
	b, err := cjson.Marshal(r)
	if err != nil {
		return nil, err
	}
	return &Signed{Signed: b}, nil
}

func (s *Signed) JSONMarshal(prefix, indent string) ([]byte, error) {
	b, err := cjson.Marshal(s)
	if err != nil {
		return []byte{}, err
	}

	var out bytes.Buffer
	if err := json.Indent(&out, b, prefix, indent); err != nil {
		return []byte{}, err
	}

	return out.Bytes(), nil
}
