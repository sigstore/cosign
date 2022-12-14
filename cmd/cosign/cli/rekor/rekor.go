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

package rekor

import (
	rekor "github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/client"

	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
)

func NewClient(rekorURL string) (*client.Rekor, error) {
	rekorClient, err := rekor.GetRekorClient(rekorURL, rekor.WithUserAgent(options.UserAgent()))
	if err != nil {
		return nil, err
	}
	return rekorClient, nil
}
