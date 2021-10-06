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

	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
	"github.com/spf13/cobra"
)

// TagOptions is a wrapper for the tag options.
type TagOptions struct {
	TagPrefix string
	TagSuffix string
}

var _ Interface = (*TagOptions)(nil)

// AddFlags implements Interface
func (o *TagOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&o.TagPrefix, "tag-prefix", "", "custom prefix to use for tags")
	cmd.Flags().StringVar(&o.TagSuffix, "tag-suffix", "", "custom suffix to use for tags")
}

func (o *TagOptions) GetTagOpts(ctx context.Context) []ociremote.Option {
	return []ociremote.Option{ociremote.WithPrefix(o.TagPrefix), ociremote.WithSuffix(o.TagSuffix)}
}
