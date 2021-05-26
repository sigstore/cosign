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

package cli

import (
	"os"
	"strconv"
)

const (
	ExperimentalEnv = "COSIGN_EXPERIMENTAL"
	ServerEnv       = "REKOR_SERVER"
	rekorServer     = "https://rekor.sigstore.dev"
)

func EnableExperimental() bool {
	if b, err := strconv.ParseBool(os.Getenv(ExperimentalEnv)); err == nil {
		return b
	}
	return false
}

// TlogServer returns the name of the tlog server, can be overwritten via env var
func TlogServer() string {
	if s := os.Getenv(ServerEnv); s != "" {
		return s
	}
	return rekorServer
}
