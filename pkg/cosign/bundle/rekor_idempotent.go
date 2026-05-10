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
	"fmt"
	"strings"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	rekorclient "github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/tle"

	"github.com/sigstore/cosign/v3/internal/ui"
	"github.com/sigstore/sigstore-go/pkg/sign"
)

// rekorClientFactory builds a Rekor v1 read client lazily. Tests inject a stub.
type rekorClientFactory func() (*client.Rekor, error)

// rekorEntryFetcher abstracts the v1 GetLogEntryByUUID lookup so tests can stub it.
type rekorEntryFetcher func(ctx context.Context, c *client.Rekor, uuid string) (*models.LogEntryAnon, error)

// rekorTLEGenerator abstracts entry-to-TLE conversion so tests can stub it.
type rekorTLEGenerator func(anon models.LogEntryAnon) (*protorekor.TransparencyLogEntry, error)

// idempotentRekor wraps an upstream sigstore-go Transparency implementation and
// treats a Rekor v1 409 conflict ("an equivalent entry already exists") as a
// success by fetching the existing entry and appending it to the bundle, matching
// the behavior of the v1 signing path in pkg/cosign/tlog.go (see issue #4851 and
// the original fix tracked in #3356).
//
// Only the Rekor v1 path is covered here. Rekor v2 does not yet expose a
// lookup-by-UUID API on its read client, so a 409 from a v2 endpoint will still
// surface to the caller; that case must be addressed in rekor-tiles.
type idempotentRekor struct {
	inner       sign.Transparency
	factory     rekorClientFactory
	fetch       rekorEntryFetcher
	generateTLE rekorTLEGenerator
}

func newIdempotentRekor(inner sign.Transparency, factory rekorClientFactory) *idempotentRekor {
	return &idempotentRekor{
		inner:       inner,
		factory:     factory,
		fetch:       defaultFetchEntry,
		generateTLE: tle.GenerateTransparencyLogEntry,
	}
}

func defaultFetchEntry(ctx context.Context, c *client.Rekor, uuid string) (*models.LogEntryAnon, error) {
	params := entries.NewGetLogEntryByUUIDParamsWithContext(ctx)
	params.SetEntryUUID(uuid)
	resp, err := c.Entries.GetLogEntryByUUID(params)
	if err != nil {
		return nil, err
	}
	for _, e := range resp.Payload {
		e := e
		return &e, nil
	}
	return nil, errors.New("empty response from rekor")
}

func (r *idempotentRekor) GetTransparencyLogEntry(ctx context.Context, keyOrCertPEM []byte, b *protobundle.Bundle) error {
	err := r.inner.GetTransparencyLogEntry(ctx, keyOrCertPEM, b)
	if err == nil {
		return nil
	}
	var existsErr *entries.CreateLogEntryConflict
	if !errors.As(err, &existsErr) {
		return err
	}
	uuid := uuidFromLocation(existsErr.Location.String())
	if uuid == "" {
		return fmt.Errorf("rekor reported an existing entry but did not return a UUID: %w", err)
	}
	rekorClient, cerr := r.factory()
	if cerr != nil {
		return fmt.Errorf("constructing rekor client to fetch existing entry %s: %w", uuid, cerr)
	}
	entry, ferr := r.fetch(ctx, rekorClient, uuid)
	if ferr != nil {
		return fmt.Errorf("fetching existing rekor entry %s after 409 conflict: %w", uuid, ferr)
	}
	tlogEntry, terr := r.generateTLE(*entry)
	if terr != nil {
		return fmt.Errorf("generating transparency log entry from existing rekor entry %s: %w", uuid, terr)
	}
	if b.VerificationMaterial == nil {
		b.VerificationMaterial = &protobundle.VerificationMaterial{}
	}
	if b.VerificationMaterial.TlogEntries == nil {
		b.VerificationMaterial.TlogEntries = []*protorekor.TransparencyLogEntry{}
	}
	b.VerificationMaterial.TlogEntries = append(b.VerificationMaterial.TlogEntries, tlogEntry)
	ui.Infof(ctx, "rekor entry already exists, reusing %s", uuid)
	return nil
}

func uuidFromLocation(loc string) string {
	loc = strings.TrimSpace(loc)
	if loc == "" {
		return ""
	}
	parts := strings.Split(loc, "/")
	return parts[len(parts)-1]
}

func newRekorClientFactory(baseURL string) rekorClientFactory {
	return func() (*client.Rekor, error) {
		return rekorclient.GetRekorClient(baseURL)
	}
}
