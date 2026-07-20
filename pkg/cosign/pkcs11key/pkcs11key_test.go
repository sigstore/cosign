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

package pkcs11key

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestErrSignerNotFound(t *testing.T) {
	err := errSignerNotFound([]byte("my-id"), []byte("my-label"))
	require.Error(t, err)
	require.True(t, errors.Is(err, SignerNotSet))
	require.Contains(t, err.Error(), "my-id")
	require.Contains(t, err.Error(), "my-label")
}
