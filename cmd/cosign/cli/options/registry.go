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
	"crypto/tls"
	"net/http"

	"github.com/google/go-containerregistry/pkg/v1/remote"
	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
	"github.com/spf13/cobra"
)

// RegistryOptions is the wrapper for the registry options.
type RegistryOptions struct {
	AllowInsecure bool
	Tags          TagOptions
}

var _ Interface = (*RegistryOptions)(nil)

// AddFlags implements Interface
func (o *RegistryOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&o.AllowInsecure, "allow-insecure-registry", false,
		"whether to allow insecure connections to registries. Don't use this for anything but testing")
	o.Tags.AddFlags(cmd)
}

func (o *RegistryOptions) ClientOpts(ctx context.Context) []ociremote.Option {
	return []ociremote.Option{ociremote.WithRemoteOptions(o.GetRegistryClientOpts(ctx)...), ociremote.WithPrefix(o.Tags.TagPrefix), ociremote.WithSuffix(o.Tags.TagSuffix)}
}

func (o *RegistryOptions) GetRegistryClientOpts(ctx context.Context) []remote.Option {
	opts := defaultRegistryClientOpts(ctx)
	if o != nil && o.AllowInsecure {
		opts = append(opts, remote.WithTransport(&http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}})) // #nosec G402
	}
	return opts
}
