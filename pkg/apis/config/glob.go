//
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

package config

import "strings"

// GlobMatch takes a string and handles only trailing '*' character as a
// wildcard. This is little different from various packages that I was able
// to find, since they handle '*' anywhere in the string as a wildcard. For our
// use we only want to handle it at the end, and hence this effectively turns
// into 'hasPrefix' string matching up to the trailing *.
func GlobMatch(image, glob string) bool {
	if !strings.HasSuffix(glob, "*") {
		// Doesn't end with *, so do an exact match
		return image == glob
	}
	return strings.HasPrefix(image, strings.TrimSuffix(glob, "*"))
}
