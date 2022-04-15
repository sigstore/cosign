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

package webhook

// PolicyResult is the result of a successful ValidatePolicy call.
// These are meant to be consumed by a higher level Policy engine that
// can reason about validated results. The 'first' level pass will verify
// signatures and attestations, and make the results then available for
// a policy that can be used to gate a passing of a ClusterImagePolicy.
// Some examples are, at least 'vulnerability' has to have been done
// and the scan must have been attested by a particular entity (sujbect/issuer)
// or a particular key.
// Other examples are N-of-M must be satisfied and so forth.
// We do not expose the low level details of signatures / attestations here
// since they have already been validated as per the Authority configuration
// and optionally by the Attestations which contain a particular policy that
// can be used to validate the Attestations (say vulnerability scanner must not
// have any High sev issues).
type PolicyResult struct {
	// AuthorityMatches will have an entry for each successful Authority check
	// on it. Key in the map is the Attestation.Name
	AuthorityMatches map[string]AuthorityMatch `json:"authorityMatches"`
}

// AuthorityMatch returns either Signatures (if there are no Attestations
// specified), or Attestations if there are Attestations specified.
type AuthorityMatch struct {
	// All of the matching signatures for this authority
	// Wonder if for consistency this should also have the matching
	// attestations name, aka, make this into a map.
	Signatures []PolicySignature `json:"signatures"`

	// Mapping from predicate type to all of the matching attestations’
	// of that type’s signature
	Attestations map[string][]PolicySignature `json:"attestations"`
}

// PolicySignature contains a normalized result of a validated signature, where
// signature could be a signature on the Image (.sig) or on an Attestation
// (.att).
type PolicySignature struct {
	// Subject that was found to match on the Cert.
	Subject string `json:"subject"`
	// Issure that was found to match on the Cert.
	Issuer string `json:"issuer"`
	// TODO(vaikas): Add all the Fulcio specific extensions here too.
	// https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md
}
