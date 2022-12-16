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

package rekor

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
)

func TestNewClient(t *testing.T) {
	t.Parallel()
	expectedUserAgent := options.UserAgent()
	requestReceived := false
	testServer := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			requestReceived = true
			file := []byte{}

			got := r.UserAgent()
			if got != expectedUserAgent {
				t.Errorf("wanted User-Agent %q, got %q", expectedUserAgent, got)
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(file)
		}))
	defer testServer.Close()

	client, err := NewClient(testServer.URL)
	if err != nil {
		t.Error(err)
	}
	_, _ = client.Tlog.GetLogInfo(nil)

	if !requestReceived {
		t.Fatal("no requests were received")
	}
}
