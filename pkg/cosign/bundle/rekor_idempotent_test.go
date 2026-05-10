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

package bundle

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/go-openapi/strfmt"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	rekorclient "github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
)

type fakeTransparency struct {
	err error
}

func (f *fakeTransparency) GetTransparencyLogEntry(_ context.Context, _ []byte, _ *protobundle.Bundle) error {
	return f.err
}

func newConflictErr(t *testing.T, location string) *entries.CreateLogEntryConflict {
	t.Helper()
	u, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	return &entries.CreateLogEntryConflict{Location: strfmt.URI(u.String())}
}

func TestIdempotentRekor_NoErrorPassesThrough(t *testing.T) {
	t.Parallel()
	inner := &fakeTransparency{err: nil}
	r := newIdempotentRekor(inner, func() (*rekorclient.Rekor, error) {
		t.Fatalf("factory should not be called when inner succeeds")
		return nil, nil
	})
	r.fetch = func(_ context.Context, _ *rekorclient.Rekor, _ string) (*models.LogEntryAnon, error) {
		t.Fatalf("fetch should not be called when inner succeeds")
		return nil, nil
	}
	r.generateTLE = func(_ models.LogEntryAnon) (*protorekor.TransparencyLogEntry, error) {
		t.Fatalf("generateTLE should not be called when inner succeeds")
		return nil, nil
	}
	bundle := &protobundle.Bundle{}
	if err := r.GetTransparencyLogEntry(context.Background(), nil, bundle); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestIdempotentRekor_NonConflictErrorPropagates(t *testing.T) {
	t.Parallel()
	innerErr := errors.New("network broke")
	r := newIdempotentRekor(&fakeTransparency{err: innerErr}, func() (*rekorclient.Rekor, error) {
		t.Fatalf("factory should not be called for non-conflict errors")
		return nil, nil
	})
	err := r.GetTransparencyLogEntry(context.Background(), nil, &protobundle.Bundle{})
	if !errors.Is(err, innerErr) {
		t.Fatalf("expected inner error to propagate, got: %v", err)
	}
}

func TestIdempotentRekor_ConflictFetchesExistingEntry(t *testing.T) {
	t.Parallel()
	conflict := newConflictErr(t, "/api/v1/log/entries/108e9186e8c5677a")
	wrappedInner := &fakeTransparency{err: conflict}

	fetched := false
	stubEntry := &models.LogEntryAnon{}
	fakeTLE := &protorekor.TransparencyLogEntry{LogIndex: 42}

	r := newIdempotentRekor(wrappedInner, func() (*rekorclient.Rekor, error) {
		return &rekorclient.Rekor{}, nil
	})
	r.fetch = func(_ context.Context, _ *rekorclient.Rekor, uuid string) (*models.LogEntryAnon, error) {
		fetched = true
		if uuid != "108e9186e8c5677a" {
			t.Fatalf("unexpected uuid: %q", uuid)
		}
		return stubEntry, nil
	}
	r.generateTLE = func(_ models.LogEntryAnon) (*protorekor.TransparencyLogEntry, error) {
		return fakeTLE, nil
	}

	bundle := &protobundle.Bundle{}
	if err := r.GetTransparencyLogEntry(context.Background(), nil, bundle); err != nil {
		t.Fatalf("expected conflict to be treated as success, got: %v", err)
	}
	if !fetched {
		t.Fatalf("expected fetch to be called for the existing entry")
	}
	if bundle.VerificationMaterial == nil {
		t.Fatalf("expected VerificationMaterial to be initialized")
	}
	if got := len(bundle.VerificationMaterial.TlogEntries); got != 1 {
		t.Fatalf("expected exactly one tlog entry, got %d", got)
	}
	if bundle.VerificationMaterial.TlogEntries[0] != fakeTLE {
		t.Fatalf("expected the stub TLE to be appended to the bundle")
	}
}

func TestIdempotentRekor_ConflictAppendsToExistingMaterial(t *testing.T) {
	t.Parallel()
	conflict := newConflictErr(t, "https://rekor.example.com/api/v1/log/entries/deadbeef")
	wrappedInner := &fakeTransparency{err: conflict}

	r := newIdempotentRekor(wrappedInner, func() (*rekorclient.Rekor, error) {
		return &rekorclient.Rekor{}, nil
	})
	r.fetch = func(_ context.Context, _ *rekorclient.Rekor, _ string) (*models.LogEntryAnon, error) {
		return &models.LogEntryAnon{}, nil
	}
	r.generateTLE = func(_ models.LogEntryAnon) (*protorekor.TransparencyLogEntry, error) {
		return &protorekor.TransparencyLogEntry{LogIndex: 7}, nil
	}

	existing := &protorekor.TransparencyLogEntry{LogIndex: 1}
	bundle := &protobundle.Bundle{
		VerificationMaterial: &protobundle.VerificationMaterial{
			TlogEntries: []*protorekor.TransparencyLogEntry{existing},
		},
	}
	if err := r.GetTransparencyLogEntry(context.Background(), nil, bundle); err != nil {
		t.Fatalf("expected conflict to be treated as success, got: %v", err)
	}
	if got := len(bundle.VerificationMaterial.TlogEntries); got != 2 {
		t.Fatalf("expected two tlog entries, got %d", got)
	}
	if bundle.VerificationMaterial.TlogEntries[0] != existing {
		t.Fatalf("expected pre-existing entry to be preserved at index 0")
	}
}

func TestIdempotentRekor_ConflictFactoryError(t *testing.T) {
	t.Parallel()
	conflict := newConflictErr(t, "/api/v1/log/entries/abc123")
	factoryErr := errors.New("cannot build client")
	r := newIdempotentRekor(&fakeTransparency{err: conflict}, func() (*rekorclient.Rekor, error) {
		return nil, factoryErr
	})

	err := r.GetTransparencyLogEntry(context.Background(), nil, &protobundle.Bundle{})
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !errors.Is(err, factoryErr) {
		t.Fatalf("expected factory error to be wrapped, got: %v", err)
	}
}

func TestIdempotentRekor_ConflictFetchError(t *testing.T) {
	t.Parallel()
	conflict := newConflictErr(t, "/api/v1/log/entries/abc123")
	fetchErr := errors.New("rekor unavailable")
	r := newIdempotentRekor(&fakeTransparency{err: conflict}, func() (*rekorclient.Rekor, error) {
		return &rekorclient.Rekor{}, nil
	})
	r.fetch = func(_ context.Context, _ *rekorclient.Rekor, _ string) (*models.LogEntryAnon, error) {
		return nil, fetchErr
	}

	err := r.GetTransparencyLogEntry(context.Background(), nil, &protobundle.Bundle{})
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !errors.Is(err, fetchErr) {
		t.Fatalf("expected fetch error to be wrapped, got: %v", err)
	}
	if !strings.Contains(err.Error(), "abc123") {
		t.Fatalf("expected error to mention the UUID, got: %v", err)
	}
}

func TestIdempotentRekor_ConflictTLEError(t *testing.T) {
	t.Parallel()
	conflict := newConflictErr(t, "/api/v1/log/entries/zzz")
	tleErr := errors.New("malformed body")
	r := newIdempotentRekor(&fakeTransparency{err: conflict}, func() (*rekorclient.Rekor, error) {
		return &rekorclient.Rekor{}, nil
	})
	r.fetch = func(_ context.Context, _ *rekorclient.Rekor, _ string) (*models.LogEntryAnon, error) {
		return &models.LogEntryAnon{}, nil
	}
	r.generateTLE = func(_ models.LogEntryAnon) (*protorekor.TransparencyLogEntry, error) {
		return nil, tleErr
	}

	err := r.GetTransparencyLogEntry(context.Background(), nil, &protobundle.Bundle{})
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !errors.Is(err, tleErr) {
		t.Fatalf("expected tle error to be wrapped, got: %v", err)
	}
}

func TestUUIDFromLocation(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"absolute path", "/api/v1/log/entries/108e9186e8c5677a", "108e9186e8c5677a"},
		{"full url", "https://rekor.example.com/api/v1/log/entries/deadbeef", "deadbeef"},
		{"trailing whitespace", "  /api/v1/log/entries/abc  ", "abc"},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := uuidFromLocation(tc.in); got != tc.want {
				t.Fatalf("uuidFromLocation(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
