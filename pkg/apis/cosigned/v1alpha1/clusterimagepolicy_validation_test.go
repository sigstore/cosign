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

package v1alpha1

import (
	"context"
	"strings"
	"testing"

	"knative.dev/pkg/apis"
)

func TestImagePatternValidation(t *testing.T) {
	tests := []struct {
		name        string
		expectErr   bool
		errorString string
		policy      ClusterImagePolicy
	}{
		{
			name:        "Should fail when both regex and glob are present: %v",
			expectErr:   true,
			errorString: "expected exactly one, got both: spec.images[0].glob, spec.images[0].regex",
			policy: ClusterImagePolicy{
				Spec: ClusterImagePolicySpec{
					Images: []ImagePattern{
						{
							Regex: "//",
							Glob:  "**",
						},
					},
				},
			},
		},
		{
			name:        "Should fail when neither regex nor glob are present: %v",
			expectErr:   true,
			errorString: "expected exactly one, got neither: spec.images[0].glob, spec.images[0].regex",
			policy: ClusterImagePolicy{
				Spec: ClusterImagePolicySpec{
					Images: []ImagePattern{
						{},
					},
				},
			},
		},
		{
			name:        "Glob should fail with multiple *: %v",
			expectErr:   true,
			errorString: "glob match supports only a single * as a trailing character",
			policy: ClusterImagePolicy{
				Spec: ClusterImagePolicySpec{
					Images: []ImagePattern{
						{
							Glob: "**",
						},
					},
				},
			},
		},
		{
			name:        "Glob should fail with non-trailing *: %v",
			expectErr:   true,
			errorString: "glob match supports only * as a trailing character",
			policy: ClusterImagePolicy{
				Spec: ClusterImagePolicySpec{
					Images: []ImagePattern{
						{
							Glob: "foo*bar",
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		err := test.policy.Validate(context.TODO())
		if test.expectErr && !strings.Contains(err.Error(), test.errorString) {
			t.Errorf(test.name, err)
		}
	}
}

func TestKeyValidation(t *testing.T) {
	tests := []struct {
		name        string
		expectErr   bool
		errorString string
		policy      ClusterImagePolicy
	}{
		{
			name:        "Should fail when key has multiple properties: %v",
			expectErr:   true,
			errorString: "expected exactly one, got both",
			policy: ClusterImagePolicy{
				Spec: ClusterImagePolicySpec{
					Images: []ImagePattern{
						{
							Glob: "myglob",
						},
					},
					Authorities: []Authority{
						{
							Key: &KeyRef{
								Data: "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaEOVJCFtduYr3xqTxeRWSW32CY/s\nTBNZj4oIUPl8JvhVPJ1TKDPlNcuT4YphSt6t3yOmMvkdQbCj8broX6vijw==\n-----END PUBLIC KEY-----",
								KMS:  "kms://key/path",
							},
						},
					},
				},
			},
		},
		{
			name:        "Should fail when key has mixed valid and invalid data: %v",
			expectErr:   true,
			errorString: "invalid value: -----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaEOVJCFtduYr3xqTxeRWSW32CY/s\nTBNZj4oIUPl8JvhVPJ1TKDPlNcuT4YphSt6t3yOmMvkdQbCj8broX6vijw==\n-----END PUBLIC KEY-----\n---somedata---",
			policy: ClusterImagePolicy{
				Spec: ClusterImagePolicySpec{
					Images: []ImagePattern{
						{
							Glob: "myglob",
						},
					},
					Authorities: []Authority{
						{
							Key: &KeyRef{
								Data: "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaEOVJCFtduYr3xqTxeRWSW32CY/s\nTBNZj4oIUPl8JvhVPJ1TKDPlNcuT4YphSt6t3yOmMvkdQbCj8broX6vijw==\n-----END PUBLIC KEY-----\n---somedata---",
							},
						},
					},
				},
			},
		},
		{
			name:        "Should fail when key has malformed pubkey data: %v",
			expectErr:   true,
			errorString: "invalid value: ---some key data----",
			policy: ClusterImagePolicy{
				Spec: ClusterImagePolicySpec{
					Images: []ImagePattern{
						{
							Glob: "myglob",
						},
					},
					Authorities: []Authority{
						{
							Key: &KeyRef{
								Data: "---some key data----",
							},
						},
					},
				},
			},
		},
		{
			name:        "Should fail when key is empty: %v",
			expectErr:   true,
			errorString: "expected exactly one, got neither",
			policy: ClusterImagePolicy{
				Spec: ClusterImagePolicySpec{
					Images: []ImagePattern{
						{
							Glob: "myglob*",
						},
					},
					Authorities: []Authority{
						{
							Key: &KeyRef{},
						},
					},
				},
			},
		},
		{
			name:        "Should fail when regex is given: %v",
			expectErr:   true,
			errorString: "must not set the field(s): spec.images[0].regex",
			policy: ClusterImagePolicy{
				Spec: ClusterImagePolicySpec{
					Images: []ImagePattern{
						{
							Regex: "myg**lob*",
						},
					},
					Authorities: []Authority{
						{
							Key: &KeyRef{
								KMS: "kms://key/path",
							},
						},
					},
				},
			},
		},
		{
			name:        "Should pass when key has only one property: %v",
			errorString: "",
			policy: ClusterImagePolicy{
				Spec: ClusterImagePolicySpec{
					Images: []ImagePattern{
						{
							Glob: "yepanotherglob",
						},
					},
					Authorities: []Authority{
						{
							Key: &KeyRef{
								KMS: "kms://key/path",
							},
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		err := test.policy.Validate(context.TODO())
		if test.expectErr && !strings.Contains(err.Error(), test.errorString) {
			t.Errorf(test.name, err)
		}
		if !test.expectErr && err != nil {
			t.Errorf(test.name, err)
		}
	}
}

func TestKeylessValidation(t *testing.T) {
	tests := []struct {
		name        string
		expectErr   bool
		errorString string
		policy      ClusterImagePolicy
	}{
		{
			name:        "Should fail when keyless is empty: %v",
			expectErr:   true,
			errorString: "expected exactly one, got neither",
			policy: ClusterImagePolicy{
				Spec: ClusterImagePolicySpec{
					Images: []ImagePattern{
						{
							Glob: "globbityglob",
						},
					},
					Authorities: []Authority{
						{
							Keyless: &KeylessRef{},
						},
					},
				},
			},
		},
		{
			name:        "Should fail when keyless has multiple properties: %v",
			expectErr:   true,
			errorString: "expected exactly one, got both",
			policy: ClusterImagePolicy{
				Spec: ClusterImagePolicySpec{
					Images: []ImagePattern{
						{
							Glob: "globbityglob",
						},
					},
					Authorities: []Authority{
						{
							Keyless: &KeylessRef{
								URL: &apis.URL{
									Host: "myhost",
								},
								CAKey: &KeyRef{
									Data: "---certificate---",
								},
							},
						},
					},
				},
			},
		},
		{
			name:        "Should pass when a valid keyless ref is specified: %v",
			errorString: "",
			policy: ClusterImagePolicy{
				Spec: ClusterImagePolicySpec{
					Images: []ImagePattern{
						{
							Glob: "globbityglob",
						},
					},
					Authorities: []Authority{
						{
							Keyless: &KeylessRef{
								URL: &apis.URL{
									Host: "myhost",
								},
							},
						},
					},
				},
			},
		},
	}
	for _, test := range tests {
		err := test.policy.Validate(context.TODO())
		if test.expectErr && !strings.Contains(err.Error(), test.errorString) {
			t.Errorf(test.name, err)
		}
		if !test.expectErr && err != nil {
			t.Errorf(test.name, err)
		}
	}
}

func TestAuthoritiesValidation(t *testing.T) {
	tests := []struct {
		name        string
		expectErr   bool
		errorString string
		policy      ClusterImagePolicy
	}{
		{
			name:        "Should fail when keyless is empty: %v",
			expectErr:   true,
			errorString: "expected exactly one, got both",
			policy: ClusterImagePolicy{
				Spec: ClusterImagePolicySpec{
					Images: []ImagePattern{
						{
							Glob: "globbityglob",
						},
					},
					Authorities: []Authority{
						{
							Key:     &KeyRef{},
							Keyless: &KeylessRef{},
						},
					},
				},
			},
		},

		{
			name:        "Should fail when keyless is empty: %v",
			expectErr:   true,
			errorString: "At least one authority should be defined",
			policy: ClusterImagePolicy{
				Spec: ClusterImagePolicySpec{
					Images: []ImagePattern{
						{
							Glob: "globbityglob",
						},
					},
					Authorities: []Authority{},
				},
			},
		},
	}
	for _, test := range tests {
		err := test.policy.Validate(context.TODO())
		if test.expectErr && !strings.Contains(err.Error(), test.errorString) {
			t.Errorf(test.name, err)
		}
		if !test.expectErr && err != nil {
			t.Errorf(test.name, err)
		}
	}
}

func TestIdentitiesValidation(t *testing.T) {
	tests := []struct {
		name        string
		expectErr   bool
		errorString string
		policy      ClusterImagePolicy
	}{
		{
			name:        "Should fail when identities is empty: %v",
			expectErr:   true,
			errorString: "At least one identity must be provided",
			policy: ClusterImagePolicy{
				Spec: ClusterImagePolicySpec{
					Images: []ImagePattern{
						{
							Glob: "globbityglob",
						},
					},
					Authorities: []Authority{
						{
							Keyless: &KeylessRef{
								Identities: []Identity{},
							},
						},
					},
				},
			},
		},
		{
			name:        "Should pass when identities is valid: %v",
			errorString: "",
			policy: ClusterImagePolicy{
				Spec: ClusterImagePolicySpec{
					Images: []ImagePattern{
						{
							Glob: "globbityglob",
						},
					},
					Authorities: []Authority{
						{
							Keyless: &KeylessRef{
								Identities: []Identity{
									{
										Issuer: "some issuer",
									},
								},
							},
						},
					},
				},
			},
		},
	}
	for _, test := range tests {
		err := test.policy.Validate(context.TODO())
		if test.expectErr && !strings.Contains(err.Error(), test.errorString) {
			t.Errorf(test.name, err)
		}
		if !test.expectErr && err != nil {
			t.Errorf(test.name, err)
		}
	}
}
