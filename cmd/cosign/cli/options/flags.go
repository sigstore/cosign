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

package options

import (
	"context"
	"flag"
	"reflect"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// OneOf ensures that only one of the supplied interfaces is set to a non-zero value.
func OneOf(args ...interface{}) bool {
	return NOf(args...) == 1
}

// NOf returns how many of the fields are non-zero
func NOf(args ...interface{}) int {
	n := 0
	for _, arg := range args {
		if !reflect.ValueOf(arg).IsZero() {
			n++
		}
	}
	return n
}

// ApplyRegistryFlags adds registry go flags to a flagset.
// Deprecated: this will be deleted when the migration to cobra is finished.
func ApplyRegistryFlags(regOpts *RegistryOptions, fs *flag.FlagSet) {
	fs.BoolVar(&regOpts.AllowInsecure, "allow-insecure-registry", false, "whether to allow insecure connections to registries. Don't use this for anything but testing")
}

func defaultRegistryClientOpts(ctx context.Context) []remote.Option {
	return []remote.Option{
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithContext(ctx),
		remote.WithUserAgent("cosign/" + VersionInfo().GitVersion),
	}
}
