// Copyright 2026 The Sigstore Authors.
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

package cli

import (
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/signature"
)

type RootOptions struct {
	Timeout time.Duration
}

type KeyOpts struct {
	KeyRef                         string
	BundlePath                     string
	SkipConfirmation               bool
	IDToken                        string
	OIDCDisableProviders           bool
	OIDCProvider                   string
	FulcioAuthFlow                 string
	OIDCClientID                   string
	OIDCClientSecret               string
	OIDCRedirectURL                string
	IssueCertificateForExistingKey bool
	SigningAlgorithm               string
	DefaultLoadOptions             *[]signature.LoadOption
	PassFunc                       func(bool) ([]byte, error)
	TrustedMaterial                root.TrustedMaterial
	SigningConfig                  *root.SigningConfig
}
