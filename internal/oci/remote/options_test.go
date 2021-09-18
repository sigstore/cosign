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
	"reflect"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/pkg/errors"
)

func TestOptions(t *testing.T) {
	ev := os.Getenv(RepoOverrideKey)
	defer os.Setenv(RepoOverrideKey, ev)
	os.Setenv(RepoOverrideKey, "gcr.io/distroless")

	repo, err := name.NewRepository("gcr.io/projectsigstore")
	if err != nil {
		t.Errorf("NewRepository() = %v", err)
	}

	overrideRepo, err := name.NewRepository("gcr.io/distroless")
	if err != nil {
		t.Errorf("NewRepository() = %v", err)
	}

	otherRepo, err := name.NewRepository("ghcr.io/distroful")
	if err != nil {
		t.Errorf("NewRepository() = %v", err)
	}

	otherROpt := []remote.Option{
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		// TODO(mattmoor): Incorporate user agent.
	}

	tests := []struct {
		name string
		opts []Option
		want *options
	}{{
		name: "no options",
		want: &options{
			SignatureSuffix:   SignatureTagSuffix,
			AttestationSuffix: AttestationTagSuffix,
			SBOMSuffix:        SBOMTagSuffix,
			TargetRepository:  overrideRepo,
			ROpt:              defaultOptions,
		},
	}, {
		name: "signature option",
		opts: []Option{WithSignatureSuffix(".pig")},
		want: &options{
			SignatureSuffix:   ".pig",
			AttestationSuffix: AttestationTagSuffix,
			SBOMSuffix:        SBOMTagSuffix,
			TargetRepository:  overrideRepo,
			ROpt:              defaultOptions,
		},
	}, {
		name: "attestation option",
		opts: []Option{WithAttestationSuffix(".pig")},
		want: &options{
			SignatureSuffix:   SignatureTagSuffix,
			AttestationSuffix: ".pig",
			SBOMSuffix:        SBOMTagSuffix,
			TargetRepository:  overrideRepo,
			ROpt:              defaultOptions,
		},
	}, {
		name: "sbom option",
		opts: []Option{WithSBOMSuffix(".pig")},
		want: &options{
			SignatureSuffix:   SignatureTagSuffix,
			AttestationSuffix: AttestationTagSuffix,
			SBOMSuffix:        ".pig",
			TargetRepository:  overrideRepo,
			ROpt:              defaultOptions,
		},
	}, {
		name: "target repo option",
		opts: []Option{WithTargetRepository(otherRepo)},
		want: &options{
			SignatureSuffix:   SignatureTagSuffix,
			AttestationSuffix: AttestationTagSuffix,
			SBOMSuffix:        SBOMTagSuffix,
			TargetRepository:  otherRepo,
			ROpt:              defaultOptions,
		},
	}, {
		name: "remote options option",
		opts: []Option{WithRemoteOptions(otherROpt...)},
		want: &options{
			SignatureSuffix:   SignatureTagSuffix,
			AttestationSuffix: AttestationTagSuffix,
			SBOMSuffix:        SBOMTagSuffix,
			TargetRepository:  overrideRepo,
			ROpt:              otherROpt,
		},
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := makeOptions(repo, test.opts...)
			if err != nil {
				t.Fatalf("makeOptions() = %v", err)
			}
			test.want.OriginalOptions = test.opts

			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("makeOptions() = %#v, wanted %#v", got, test.want)
			}
		})
	}
}

func TestOptionsErrors(t *testing.T) {
	repo, err := name.NewRepository("gcr.io/projectsigstore")
	if err != nil {
		t.Errorf("NewRepository() = %v", err)
	}

	want := errors.New("you should expect this error")

	_, got := makeOptions(repo, func(*options) error {
		return want
	})
	if !errors.Is(got, want) {
		t.Fatalf("makeOptions() = %#v, wanted %v", got, want)
	}

	ev := os.Getenv(RepoOverrideKey)
	defer os.Setenv(RepoOverrideKey, ev)
	os.Setenv(RepoOverrideKey, "gcr.io/illegal@character")

	want = errors.New("repository can only contain the runes `abcdefghijklmnopqrstuvwxyz0123456789_-./`: illegal@character")
	_, got = makeOptions(repo)
	if got.Error() != want.Error() {
		t.Fatalf("makeOptions() = %v, wanted %v", got, want)
	}
}
