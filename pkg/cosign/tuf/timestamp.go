// Copyright 2022 The Sigstore Authors.
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
	"context"
	"encoding/json"

	"github.com/pkg/errors"
	"github.com/theupdateframework/go-tuf/data"
)

// GetTimestamp fetches the TUF timestamp metadata to be bundled
// with the OCI signature.
func GetTimestamp(ctx context.Context) (*Timestamp, error) {
	tuf, err := NewFromEnv(ctx)
	if err != nil {
		return nil, err
	}
	defer tuf.Close()
	tsBytes, err := tuf.GetTimestamp()
	if err != nil {
		return nil, err
	}
	var timestamp Timestamp
	if err := json.Unmarshal(tsBytes, &timestamp); err != nil {
		return nil, errors.Wrap(err, "unable to unmarshal timestamp")
	}
	return &timestamp, nil
}

type Timestamp struct {
	Signatures []data.Signature `json:"signatures"`
	Signed     data.Timestamp   `json:"signed"`
}
