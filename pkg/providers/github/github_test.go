//
// Copyright 2025 The Sigstore Authors.
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

package github

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/sigstore/cosign/v3/pkg/cosign/env"
)

func TestProvide_NoDuplicateAuthHeaders(t *testing.T) {
	var attempts atomic.Int32

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)

		// Verify exactly one Authorization header on every attempt.
		authHeaders := r.Header.Values("Authorization")
		if len(authHeaders) != 1 {
			t.Errorf("attempt %d: want 1 Authorization header, got %d: %v", n, len(authHeaders), authHeaders)
		}

		if n < 3 {
			// Force retries by closing the connection.
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Fatal("server does not support hijacking")
			}
			conn, _, err := hj.Hijack()
			if err != nil {
				t.Fatal(err)
			}
			conn.Close()
			return
		}

		// Succeed on the 3rd attempt.
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"value":"test-token"}`)) //nolint:errcheck
	}))
	defer ts.Close()

	t.Setenv(env.VariableGitHubRequestToken.String(), "fake-token")
	// The provider appends "&audience=..." so the base URL needs a query param.
	t.Setenv(env.VariableGitHubRequestURL.String(), ts.URL+"?test=1")

	ga := &githubActions{}
	token, err := ga.Provide(context.Background(), "sigstore")
	if err != nil {
		t.Fatalf("Provide: %v", err)
	}
	if token != "test-token" {
		t.Errorf("want token %q, got %q", "test-token", token)
	}
	if got := attempts.Load(); got != 3 {
		t.Errorf("want 3 attempts, got %d", got)
	}
}

func TestProvide_ErrorResponse(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		body    string
		want    []string
		notWant []string
	}{{
		name:    "non-JSON body on a failing status",
		status:  http.StatusBadGateway,
		body:    "upstream connect error or disconnect/reset before headers",
		want:    []string{"github-actions", "502", "upstream connect error or disconnect/reset before headers"},
		notWant: []string{"invalid character"},
	}, {
		name:    "long error body is truncated",
		status:  http.StatusInternalServerError,
		body:    strings.Repeat("x", maxErrorBodyBytes+100),
		want:    []string{"github-actions", "500"},
		notWant: []string{strings.Repeat("x", maxErrorBodyBytes+1)},
	}, {
		name:   "empty error body",
		status: http.StatusServiceUnavailable,
		body:   "",
		want:   []string{"github-actions", "503"},
	}, {
		name:   "malformed JSON body on success",
		status: http.StatusOK,
		body:   "not json",
		want:   []string{"invalid identity token response from provider github-actions"},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				w.Write([]byte(tt.body)) //nolint:errcheck
			}))
			defer ts.Close()

			t.Setenv(env.VariableGitHubRequestToken.String(), "fake-token")
			// The provider appends "&audience=..." so the base URL needs a query param.
			t.Setenv(env.VariableGitHubRequestURL.String(), ts.URL+"?test=1")

			ga := &githubActions{}
			_, err := ga.Provide(context.Background(), "sigstore")
			if err == nil {
				t.Fatal("Provide: want error, got nil")
			}
			for _, want := range tt.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("want error containing %q, got %q", want, err)
				}
			}
			for _, notWant := range tt.notWant {
				if strings.Contains(err.Error(), notWant) {
					t.Errorf("want error without %q, got %q", notWant, err)
				}
			}
		})
	}
}
