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
			errorString: "expected exactly one, got both",
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
			errorString: "expected exactly one, got neither",
			policy: ClusterImagePolicy{
				Spec: ClusterImagePolicySpec{
					Images: []ImagePattern{
						{},
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
							Regex: "//",
							Authorities: []Authority{
								{
									Key: &KeyRef{
										Data: "---some key data----",
										KMS:  "kms://key/path",
									},
								},
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
							Regex: "//",
							Authorities: []Authority{
								{
									Key: &KeyRef{},
								},
							},
						},
					},
				},
			},
		},
		{
			name:        "Should pass when key has only one property: %v",
			expectErr:   false,
			errorString: "",
			policy: ClusterImagePolicy{
				Spec: ClusterImagePolicySpec{
					Images: []ImagePattern{
						{
							Regex: "//",
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
							Regex: "//",
							Authorities: []Authority{
								{
									Keyless: &KeylessRef{},
								},
							},
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
							Regex: "//",
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
			},
		},
		{
			name:        "Should pass when a valid keyless ref is specified: %v",
			expectErr:   false,
			errorString: "",
			policy: ClusterImagePolicy{
				Spec: ClusterImagePolicySpec{
					Images: []ImagePattern{
						{
							Regex: "//",
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
							Regex: "//",
							Authorities: []Authority{
								{
									Key:     &KeyRef{},
									Keyless: &KeylessRef{},
								},
							},
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
							Regex:       "//",
							Authorities: []Authority{},
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
							Regex: "//",
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
			},
		},
		{
			name:        "Should pass when identities is valid: %v",
			expectErr:   false,
			errorString: "",
			policy: ClusterImagePolicy{
				Spec: ClusterImagePolicySpec{
					Images: []ImagePattern{
						{
							Regex: "//",
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
