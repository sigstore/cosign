// Copyright 2023 The Sigstore Authors.
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

package client

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/digitorus/timestamp"
	"github.com/pkg/errors"
)

// TimestampAuthorityClient should be implemented by clients that want to request timestamp responses
type TimestampAuthorityClient interface {
	GetTimestampResponse(tsq []byte) ([]byte, error)
}

// TimestampAuthorityClient provides a client to query RFC 3161 timestamp authorities
type TimestampAuthorityClientImpl struct {
	TimestampAuthorityClient

	// URL is the path to the API to request timestamp responses
	URL string

	// Timeout is the request timeout
	Timeout time.Duration
}

// GetTimestampResponse sends a timestamp query to a timestamp authority, returning a timestamp response.
// The query and response are defined by RFC 3161.
func (t *TimestampAuthorityClientImpl) GetTimestampResponse(tsq []byte) ([]byte, error) {
	client := http.Client{
		Timeout: t.Timeout,
	}
	req, err := http.NewRequest("POST", t.URL, bytes.NewReader(tsq))
	if err != nil {
		return nil, errors.Wrap(err, "error creating HTTP request")
	}
	req.Header.Set("Content-Type", "application/timestamp-query")

	tsr, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "error making request to timestamp authority")
	}
	if tsr.StatusCode != 200 && tsr.StatusCode != 201 {
		return nil, fmt.Errorf("request to timestamp authority failed with status code %d", tsr.StatusCode)
	}

	resp, err := io.ReadAll(tsr.Body)
	if err != nil {
		return nil, errors.Wrap(err, "error reading timestamp response")
	}

	// validate that the timestamp response is parseable
	ts, err := timestamp.ParseResponse(resp)
	if err != nil {
		return nil, err
	}

	fmt.Fprintln(os.Stderr, "Timestamp fetched with time: ", ts.Time)

	return resp, nil
}

func NewTSAClient(url string) *TimestampAuthorityClientImpl {
	return &TimestampAuthorityClientImpl{URL: url, Timeout: 10 * time.Second}
}
