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
	"net"
	"time"

	"github.com/cenkalti/backoff/v4"
)

const (
	defaultMaxRetries = 3
	defaultMaxElapsed = 30 * time.Second
)

// Retriable wraps an error to indicate it can be retried.
type Retriable struct {
	Err error
}

func (r *Retriable) Error() string { return r.Err.Error() }
func (r *Retriable) Unwrap() error { return r.Err }

// HTTPError represents an HTTP error with a status code.
type HTTPError interface {
	error
	Code() int
}

// IsRetriable checks if an error should be retried.
// Retriable errors are: network errors, 5xx server errors, and 429 rate limits.
func IsRetriable(err error) bool {
	if err == nil {
		return false
	}

	// Explicit retriable wrapper
	var r *Retriable
	if errors.As(err, &r) {
		return true
	}

	// Network errors (DNS, connection refused, timeout)
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}

	// HTTP status code checks
	var httpErr HTTPError
	if errors.As(err, &httpErr) {
		code := httpErr.Code()
		// 429 Too Many Requests or 5xx Server Errors
		return code == 429 || (code >= 500 && code <= 599)
	}

	return false
}

// Do runs fn with exponential backoff. fn is retried only when it returns
// an error that IsRetriable considers transient.
func Do(ctx context.Context, fn func() error) error {
	bo := backoff.NewExponentialBackOff()
	bo.MaxElapsedTime = defaultMaxElapsed

	retryCount := 0
	wrapped := func() error {
		err := fn()
		if err == nil {
			return nil
		}
		if !IsRetriable(err) {
			return backoff.Permanent(err)
		}
		retryCount++
		if retryCount > defaultMaxRetries {
			return backoff.Permanent(fmt.Errorf("max retries exceeded: %w", err))
		}
		return err
	}

	return backoff.Retry(wrapped, backoff.WithContext(bo, ctx))
}
