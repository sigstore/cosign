//
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

package options

const SBOMAttachmentDeprecation = "WARNING: SBOM attachments are deprecated " +
	"and support will be removed in a Cosign release soon after 2024-02-22 " +
	"(see https://github.com/sigstore/cosign/issues/2755). " +
	"Instead, please use SBOM attestations."

const RootWithoutChecksumDeprecation = "WARNING: Fetching initial root from URL " +
	"without providing its checksum is deprecated and will be disallowed in " +
	"a future Cosign release. Please provide the initial root checksum " +
	"via the --root-checksum argument."
