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

package cli

import (
	"context"
	"crypto/tls"
	"flag"
	"net/http"
	"reflect"

	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// oneOf ensures that only one of the supplied interfaces is set to a non-zero value.
func oneOf(args ...interface{}) bool {
	return nOf(args...) == 1
}

// nOf returns how many of the fields are non-zero
func nOf(args ...interface{}) int {
	n := 0
	for _, arg := range args {
		if !reflect.ValueOf(arg).IsZero() {
			n++
		}
	}
	return n
}

type RegistryOpts struct {
	AllowInsecure bool
}

func (co *RegistryOpts) GetRegistryClientOpts(ctx context.Context) []remote.Option {
	opts := defaultRegistryClientOpts(ctx)
	if co != nil && co.AllowInsecure {
		opts = append(opts, remote.WithTransport(&http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}})) // #nosec G402
	}
	return opts
}

func ApplyRegistryFlags(regOpts *RegistryOpts, fs *flag.FlagSet) {
	fs.BoolVar(&regOpts.AllowInsecure, "allow-insecure-registry", false, "whether to allow insecure connections to registries. Don't use this for anything but testing")
}
