// Copyright 2024 The Sigstore Authors.
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

package retry

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

type testHTTPError struct {
	code int
	msg  string
}

func (e *testHTTPError) Error() string { return e.msg }
func (e *testHTTPError) Code() int     { return e.code }

func TestIsRetriable(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"plain error", errors.New("something broke"), false},
		{"500 server error", &testHTTPError{500, "internal server error"}, true},
		{"502 bad gateway", &testHTTPError{502, "bad gateway"}, true},
		{"503 unavailable", &testHTTPError{503, "service unavailable"}, true},
		{"429 rate limit", &testHTTPError{429, "too many requests"}, true},
		{"400 bad request", &testHTTPError{400, "bad request"}, false},
		{"403 forbidden", &testHTTPError{403, "forbidden"}, false},
		{"404 not found", &testHTTPError{404, "not found"}, false},
		{"retriable wrapper", &Retriable{Err: errors.New("transient")}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsRetriable(tt.err); got != tt.want {
				t.Errorf("IsRetriable() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDo_Success(t *testing.T) {
	calls := 0
	err := Do(context.Background(), func() error {
		calls++
		return nil
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 call, got %d", calls)
	}
}

func TestDo_RetryThenSuccess(t *testing.T) {
	calls := 0
	err := Do(context.Background(), func() error {
		calls++
		if calls < 3 {
			return &testHTTPError{503, "unavailable"}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if calls != 3 {
		t.Fatalf("expected 3 calls, got %d", calls)
	}
}

func TestDo_NonRetriableError(t *testing.T) {
	calls := 0
	err := Do(context.Background(), func() error {
		calls++
		return &testHTTPError{403, "forbidden"}
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if calls != 1 {
		t.Fatalf("expected 1 call (no retry for 403), got %d", calls)
	}
}

func TestDo_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := Do(ctx, func() error {
		return fmt.Errorf("should not run")
	})
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}
