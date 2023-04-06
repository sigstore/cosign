//
// Copyright 2023 The Sigstore Authors.
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

package envvar

import (
	"context"

	"github.com/sigstore/cosign/v2/pkg/cosign/env"
	"github.com/sigstore/cosign/v2/pkg/providers"
)

func init() {
	providers.Register("envvar", &envvar{})
}

type envvar struct{}

var _ providers.Interface = (*envvar)(nil)

// Enabled implements providers.Interface
func (p *envvar) Enabled(context.Context) bool {
	_, ok := env.LookupEnv(env.VariableSigstoreIDToken)
	return ok
}

// Provide implements providers.Interface
func (p *envvar) Provide(context.Context, string) (string, error) {
	return env.Getenv(env.VariableSigstoreIDToken), nil
}
