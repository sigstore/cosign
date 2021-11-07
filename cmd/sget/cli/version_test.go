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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sigstore/cosign/pkg/version"
)

func TestVersionText(t *testing.T) {
	sut := version.GetVersionInfo()
	require.NotEmpty(t, sut.String())
}

func TestVersionJSON(t *testing.T) {
	sut := version.GetVersionInfo()
	json, err := sut.JSONString()

	require.Nil(t, err)
	require.NotEmpty(t, json)
}
