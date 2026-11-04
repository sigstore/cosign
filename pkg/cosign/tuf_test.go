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

package cosign

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTrustedRootWithContextStopsRefresh(t *testing.T) {
	t.Setenv("TUF_ROOT", t.TempDir())
	refreshRunning := func() bool {
		buf := make([]byte, 1<<20)
		return strings.Contains(string(buf[:runtime.Stack(buf, true)]), "root.NewLiveTrustedRootFromTargetWithPeriod.func")
	}
	ctx, cancel := context.WithCancel(context.Background())

	trustedRoot, err := TrustedRootWithContext(ctx)
	require.NoError(t, err)
	require.NotNil(t, trustedRoot)
	require.True(t, refreshRunning())

	cancel()
	assert.Eventually(t, func() bool { return !refreshRunning() }, 5*time.Second, 10*time.Millisecond)
}
