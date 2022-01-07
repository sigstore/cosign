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

package tuf

import (
	"context"
	"os"
	"testing"
)

var targets = []string{
	"fulcio.crt.pem",
	"fulcio_v1.crt.pem",
	"ctfe.pub",
	"rekor.pub",
}

func TestNewFromEnv(t *testing.T) {
	td := t.TempDir()
	t.Setenv("TUF_ROOT", td)
	ctx := context.Background()

	// Make sure nothing is expired
	tuf, err := NewFromEnv(ctx)
	if err != nil {
		t.Fatal(err)
	}

	checkTargetsAndMeta(t, tuf)
	tuf.Close()

	// Now try with expired targets
	forceExpiration(t, true)
	tuf, err = NewFromEnv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tuf.Close()
	checkTargetsAndMeta(t, tuf)

	// Now let's explicitly make a root.
	remote, err := GcsRemoteStore(ctx, DefaultRemoteRoot, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := Initialize(remote, nil); err != nil {
		t.Error()
	}
	if l := dirLen(t, td); l == 0 {
		t.Errorf("expected filesystem writes, got %d entries", l)
	}

	// And go from there!
	tuf, err = NewFromEnv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	checkTargetsAndMeta(t, tuf)
	tuf.Close()
}

func TestNoCache(t *testing.T) {
	ctx := context.Background()
	// Once more with NO_CACHE
	t.Setenv("SIGSTORE_NO_CACHE", "true")
	td := t.TempDir()
	t.Setenv("TUF_ROOT", td)

	// Force expiration so we have some content to download
	forceExpiration(t, true)

	tuf, err := NewFromEnv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	checkTargetsAndMeta(t, tuf)
	tuf.Close()

	if l := dirLen(t, td); l != 0 {
		t.Errorf("expected no filesystem writes, got %d entries", l)
	}
}

func TestCache(t *testing.T) {
	ctx := context.Background()
	// Once more with NO_CACHE
	t.Setenv("SIGSTORE_NO_CACHE", "false")
	td := t.TempDir()
	t.Setenv("TUF_ROOT", td)

	// Make sure nothing is in that directory to start with
	if l := dirLen(t, td); l != 0 {
		t.Errorf("expected no filesystem writes, got %d entries", l)
	}

	// Nothing should get downloaded if everything is up to date
	forceExpiration(t, false)
	tuf, err := NewFromEnv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tuf.Close()

	if l := dirLen(t, td); l != 0 {
		t.Errorf("expected no filesystem writes, got %d entries", l)
	}

	// Force expiration so that content gets downloaded. This should write to disk
	forceExpiration(t, true)
	tuf, err = NewFromEnv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tuf.Close()

	if l := dirLen(t, td); l == 0 {
		t.Errorf("expected filesystem writes, got %d entries", l)
	}
	checkTargetsAndMeta(t, tuf)
}

func checkTargetsAndMeta(t *testing.T, tuf *TUF) {
	// Check the targets
	t.Helper()
	for _, target := range targets {
		if _, err := tuf.GetTarget(target); err != nil {
			t.Fatal(err)
		}
	}

	// An invalid target
	if _, err := tuf.GetTarget("invalid"); err == nil {
		t.Error("expected error reading target, got nil")
	}

	// Check the TUF timestamp metadata
	if ts, err := tuf.GetTimestamp(); err != nil {
		t.Error("expected no error reading timestamp, got err")
	} else if len(ts) == 0 {
		t.Errorf("expected timestamp length of %d, got 0", len(ts))
	}
}

func dirLen(t *testing.T, td string) int {
	t.Helper()
	de, err := os.ReadDir(td)
	if err != nil {
		t.Fatal(err)
	}
	return len(de)
}

func forceExpiration(t *testing.T, expire bool) {
	oldIsExpiredMetadata := isExpiredMetadata
	isExpiredMetadata = func(_ []byte) bool {
		return expire
	}
	t.Cleanup(func() {
		isExpiredMetadata = oldIsExpiredMetadata
	})
}
