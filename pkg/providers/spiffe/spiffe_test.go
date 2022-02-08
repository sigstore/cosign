// Copyright 2022 The Sigstore Authors.
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

package spiffe

import (
	"os"

	"testing"
)

const nonDefault = "/run/sockets/spire"

func TestGetSocketPath(t *testing.T) {
	if got := getSocketPath(); got != defaultSocketPath {
		t.Errorf("Expected %s got %s", defaultSocketPath, got)
	}
	os.Setenv(socketEnv, nonDefault)
	if got := getSocketPath(); got != nonDefault {
		t.Errorf("Expected %s got %s", nonDefault, got)
	}
}
