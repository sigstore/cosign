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

package remote

import (
	"os"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

const (
	SignatureTagSuffix   = ".sig"
	SBOMTagSuffix        = ".sbom"
	AttestationTagSuffix = ".att"

	RepoOverrideKey = "COSIGN_REPOSITORY"
)

// Option is a functional option for remote operations.
type Option func(*options) error

type options struct {
	SignatureSuffix   string
	AttestationSuffix string
	SBOMSuffix        string
	TargetRepository  name.Repository
	ROpt              []remote.Option

	OriginalOptions []Option
}

var defaultOptions = []remote.Option{
	remote.WithAuthFromKeychain(authn.DefaultKeychain),
	// TODO(mattmoor): Incorporate user agent.
}

func makeOptions(target name.Repository, opts ...Option) (*options, error) {
	o := &options{
		SignatureSuffix:   SignatureTagSuffix,
		AttestationSuffix: AttestationTagSuffix,
		SBOMSuffix:        SBOMTagSuffix,
		TargetRepository:  target,
		ROpt:              defaultOptions,

		// Keep the original options around for things that want
		// to call something that takes options!
		OriginalOptions: opts,
	}

	// Before applying options, allow the environment to override things.
	if ro := os.Getenv(RepoOverrideKey); ro != "" {
		repo, err := name.NewRepository(ro)
		if err != nil {
			return nil, err
		}
		o.TargetRepository = repo
	}

	for _, option := range opts {
		if err := option(o); err != nil {
			return nil, err
		}
	}

	return o, nil
}

// WithSignatureSuffix is a functional option for overriding the default
// signature tag suffix.
func WithSignatureSuffix(suffix string) Option {
	return func(o *options) error {
		o.SignatureSuffix = suffix
		return nil
	}
}

// WithAttestationSuffix is a functional option for overriding the default
// attestation tag suffix.
func WithAttestationSuffix(suffix string) Option {
	return func(o *options) error {
		o.AttestationSuffix = suffix
		return nil
	}
}

// WithSBOMSuffix is a functional option for overriding the default
// SBOM tag suffix.
func WithSBOMSuffix(suffix string) Option {
	return func(o *options) error {
		o.SBOMSuffix = suffix
		return nil
	}
}

// WithRemoteOptions is a functional option for overriding the default
// remote options passed to GGCR.
func WithRemoteOptions(opts ...remote.Option) Option {
	return func(o *options) error {
		o.ROpt = opts
		return nil
	}
}

// WithTargetRepository is a functional option for overriding the default
// target repository hosting the signature and attestation tags.
func WithTargetRepository(repo name.Repository) Option {
	return func(o *options) error {
		o.TargetRepository = repo
		return nil
	}
}
