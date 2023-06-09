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

package all

import (
	"github.com/sigstore/cosign/v2/pkg/providers"

	// Link in all of the providers.
	// Link the GitHub one first, since we might be running in a GitHub self-hosted
	// runner running in one of the other environments, and we should prefer GitHub
	// credentials if we can find them.
	_ "github.com/sigstore/cosign/v2/pkg/providers/github"

	// Link in the rest of the providers.
	_ "github.com/sigstore/cosign/v2/pkg/providers/buildkite"
	_ "github.com/sigstore/cosign/v2/pkg/providers/envvar"
	_ "github.com/sigstore/cosign/v2/pkg/providers/filesystem"
	_ "github.com/sigstore/cosign/v2/pkg/providers/google"
	_ "github.com/sigstore/cosign/v2/pkg/providers/spiffe"
)

// Alias these methods, so that folks can import this to get all providers.
var (
	Enabled     = providers.Enabled
	Provide     = providers.Provide
	ProvideFrom = providers.ProvideFrom
)
