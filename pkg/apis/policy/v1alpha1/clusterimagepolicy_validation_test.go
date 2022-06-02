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
	"testing"

	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
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
			name:        "Should fail when glob is not present",
			expectErr:   true,
			errorString: "missing field(s): spec.authorities, spec.images[0].glob",
			policy: ClusterImagePolicy{
				Spec: ClusterImagePolicySpec{
					Images: []ImagePattern{
						{},
					},
				},
			},
		},
		{
			name:        "Glob should fail with invalid glob",
			expectErr:   true,
			errorString: "invalid value: [: spec.images[0].glob\nglob is invalid: syntax error in pattern\nmissing field(s): spec.authorities",
			policy: ClusterImagePolicy{
				Spec: ClusterImagePolicySpec{
					Images: []ImagePattern{
						{
							Glob: "[",
						},
					},
				},
			},
		},
		{
			name:        "missing image and authorities in the spec",
			expectErr:   true,
			errorString: "missing field(s): spec.authorities, spec.images",
			policy: ClusterImagePolicy{
				Spec: ClusterImagePolicySpec{},
			},
		},
		{
			name:        "Should fail when glob is invalid: %v",
			expectErr:   true,
			errorString: "missing field(s): spec.authorities",
			policy: ClusterImagePolicy{
				Spec: ClusterImagePolicySpec{
					Images: []ImagePattern{
						{
							Glob: "]",
						},
					},
				},
			},
		},
		{
			name:      "Should pass when glob is valid: %v",
			expectErr: false,
			policy: ClusterImagePolicy{
				Spec: ClusterImagePolicySpec{
					Images: []ImagePattern{
						{
							Glob: "gcr.io/*",
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
		t.Run(test.name, func(t *testing.T) {
			err := test.policy.Validate(context.TODO())
			if test.expectErr {
				require.NotNil(t, err)
				require.EqualError(t, err, test.errorString)
			} else {
				require.Nil(t, err)
			}
		})
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
			name:        "Should fail when key has multiple properties",
			expectErr:   true,
			errorString: "expected exactly one, got both: spec.authorities[0].key.data, spec.authorities[0].key.kms, spec.authorities[0].key.secretref",
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
			name:        "Should fail when key has mixed valid and invalid data",
			expectErr:   true,
			errorString: "invalid value: -----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaEOVJCFtduYr3xqTxeRWSW32CY/s\nTBNZj4oIUPl8JvhVPJ1TKDPlNcuT4YphSt6t3yOmMvkdQbCj8broX6vijw==\n-----END PUBLIC KEY-----\n---somedata---: spec.authorities[0].key.data",
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
			name:        "Should fail when key has malformed pubkey data",
			expectErr:   true,
			errorString: "invalid value: ---some key data----: spec.authorities[0].key.data",
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
			name:        "Should fail when key is empty",
			expectErr:   true,
			errorString: "expected exactly one, got neither: spec.authorities[0].key.data, spec.authorities[0].key.kms, spec.authorities[0].key.secretref",
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
		t.Run(test.name, func(t *testing.T) {
			err := test.policy.Validate(context.TODO())
			if test.expectErr {
				require.NotNil(t, err)
				require.EqualError(t, err, test.errorString)
			} else {
				require.Nil(t, err)
			}
		})
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
			name:        "Should fail when keyless is empty",
			expectErr:   true,
			errorString: "expected exactly one, got neither: spec.authorities[0].keyless.ca-cert, spec.authorities[0].keyless.identities, spec.authorities[0].keyless.url",
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
			name:        "Should fail when keyless has multiple properties",
			expectErr:   true,
			errorString: "expected exactly one, got both: spec.authorities[0].keyless.ca-cert, spec.authorities[0].keyless.url",
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
								CACert: &KeyRef{
									Data: "---certificate---",
								},
							},
						},
					},
				},
			},
		},
		{
			name:      "Should pass when a valid keyless ref is specified",
			expectErr: false,
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
		t.Run(test.name, func(t *testing.T) {
			err := test.policy.Validate(context.TODO())
			if test.expectErr {
				require.NotNil(t, err)
				require.EqualError(t, err, test.errorString)
			} else {
				require.Nil(t, err)
			}
		})
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
			name:        "Should fail when keyless is empty",
			expectErr:   true,
			errorString: "expected exactly one, got both: spec.authorities[0].key, spec.authorities[0].keyless\nexpected exactly one, got neither: spec.authorities[0].key.data, spec.authorities[0].key.kms, spec.authorities[0].key.secretref, spec.authorities[0].keyless.ca-cert, spec.authorities[0].keyless.identities, spec.authorities[0].keyless.url",
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
			name:        "Should fail when keyless is empty",
			expectErr:   true,
			errorString: "missing field(s): spec.authorities",
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
		{
			name:      "Should pass when source oci is present",
			expectErr: false,
			policy: ClusterImagePolicy{
				Spec: ClusterImagePolicySpec{
					Images: []ImagePattern{{Glob: "gcr.io/*"}},
					Authorities: []Authority{
						{
							Key:     &KeyRef{KMS: "kms://key/path"},
							Sources: []Source{{OCI: "registry.example.com"}},
						},
					},
				},
			},
		},
		{
			name:        "Should fail when source oci is empty",
			expectErr:   true,
			errorString: "missing field(s): spec.authorities[0].source[0].oci",
			policy: ClusterImagePolicy{
				Spec: ClusterImagePolicySpec{
					Images: []ImagePattern{{Glob: "gcr.io/*"}},
					Authorities: []Authority{
						{
							Key:     &KeyRef{KMS: "kms://key/path"},
							Sources: []Source{{OCI: ""}},
						},
					},
				},
			},
		},
		{
			name:      "Should pass with multiple source oci is present",
			expectErr: false,
			policy: ClusterImagePolicy{
				Spec: ClusterImagePolicySpec{
					Images: []ImagePattern{{Glob: "gcr.io/*"}},
					Authorities: []Authority{
						{
							Key: &KeyRef{KMS: "kms://key/path"},
							Sources: []Source{
								{OCI: "registry1"},
								{OCI: "registry2"},
							},
						},
					},
				},
			},
		},
		{
			name:      "Should pass with multiple source oci is present",
			expectErr: false,
			policy: ClusterImagePolicy{
				Spec: ClusterImagePolicySpec{
					Images: []ImagePattern{{Glob: "gcr.io/*"}},
					Authorities: []Authority{
						{
							Key: &KeyRef{KMS: "kms://key/path"},
							Sources: []Source{
								{OCI: "registry1"},
								{OCI: "registry2"},
							},
						},
					},
				},
			},
		},
		{
			name:      "Should pass with attestations present",
			expectErr: false,
			policy: ClusterImagePolicy{
				Spec: ClusterImagePolicySpec{
					Images: []ImagePattern{{Glob: "gcr.io/*"}},
					Authorities: []Authority{
						{
							Key: &KeyRef{KMS: "kms://key/path"},
							Attestations: []Attestation{
								{Name: "first", PredicateType: "vuln"},
								{Name: "second", PredicateType: "custom", Policy: &Policy{
									Type: "cue",
									Data: `predicateType: "cosign.sigstore.dev/attestation/vuln/v1"`,
								},
								},
							},
						},
					},
				},
			},
		},
		{
			name:        "Should fail with signaturePullSecret name empty",
			expectErr:   true,
			errorString: "missing field(s): spec.authorities[0].source[0].signaturePullSecrets[0].name",
			policy: ClusterImagePolicy{
				Spec: ClusterImagePolicySpec{
					Images: []ImagePattern{{Glob: "gcr.io/*"}},
					Authorities: []Authority{
						{
							Key: &KeyRef{KMS: "kms://key/path"},
							Sources: []Source{
								{
									OCI: "registry1",
									SignaturePullSecrets: []v1.LocalObjectReference{
										{Name: ""},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name:      "Should pass with signaturePullSecret name filled",
			expectErr: false,
			policy: ClusterImagePolicy{
				Spec: ClusterImagePolicySpec{
					Images: []ImagePattern{{Glob: "gcr.io/*"}},
					Authorities: []Authority{
						{
							Key: &KeyRef{KMS: "kms://key/path"},
							Sources: []Source{
								{
									OCI: "registry1",
									SignaturePullSecrets: []v1.LocalObjectReference{
										{Name: "testPullSecrets"},
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
		t.Run(test.name, func(t *testing.T) {
			err := test.policy.Validate(context.TODO())
			if test.expectErr {
				require.NotNil(t, err)
				require.EqualError(t, err, test.errorString)
			} else {
				require.Nil(t, err)
			}
		})
	}
}

func TestAttestationsValidation(t *testing.T) {
	tests := []struct {
		name        string
		expectErr   bool
		errorString string
		attestation Attestation
	}{{
		name:        "vuln",
		attestation: Attestation{Name: "first", PredicateType: "vuln"},
	}, {
		name:        "missing name",
		attestation: Attestation{PredicateType: "vuln"},
		expectErr:   true,
		errorString: "missing field(s): name",
	}, {
		name:        "missing predicatetype",
		attestation: Attestation{Name: "first"},
		expectErr:   true,
		errorString: "missing field(s): predicateType",
	}, {
		name:        "invalid predicatetype",
		attestation: Attestation{Name: "first", PredicateType: "notsupported"},
		expectErr:   true,
		errorString: "invalid value: notsupported: predicateType\nunsupported precicate type",
	}, {
		name: "custom with invalid policy type",
		attestation: Attestation{Name: "second", PredicateType: "custom",
			Policy: &Policy{
				Type: "not-cue",
				Data: `predicateType: "cosign.sigstore.dev/attestation/vuln/v1"`,
			},
		},
		expectErr:   true,
		errorString: "invalid value: not-cue: policy.type\nonly cue is supported at the moment",
	}, {
		name: "custom with missing policy data",
		attestation: Attestation{Name: "second", PredicateType: "custom",
			Policy: &Policy{
				Type: "cue",
			},
		},
		expectErr:   true,
		errorString: "missing field(s): policy.data",
	}, {
		name: "custom with policy",
		attestation: Attestation{Name: "second", PredicateType: "custom",
			Policy: &Policy{
				Type: "cue",
				Data: `predicateType: "cosign.sigstore.dev/attestation/vuln/v1"`,
			},
		},
	},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.attestation.Validate(context.TODO())
			if test.expectErr {
				require.NotNil(t, err)
				require.EqualError(t, err, test.errorString)
			} else {
				require.Nil(t, err)
			}
		})
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
			name:        "Should fail when identities is empty",
			expectErr:   true,
			errorString: "missing field(s): spec.authorities[0].keyless.identities",
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
			name:        "Should fail when issuer has invalid regex",
			expectErr:   true,
			errorString: "invalid value: ****: spec.authorities[0].keyless.identities[0].issuer\nregex is invalid: error parsing regexp: missing argument to repetition operator: `*`",
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
								Identities: []Identity{{Issuer: "****"}},
							},
						},
					},
				},
			},
		},
		{
			name:        "Should fail when subject has invalid regex",
			expectErr:   true,
			errorString: "invalid value: ****: spec.authorities[0].keyless.identities[0].subject\nregex is invalid: error parsing regexp: missing argument to repetition operator: `*`",
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
								Identities: []Identity{{Subject: "****"}},
							},
						},
					},
				},
			},
		},
		{
			name: "Should pass when subject and issuer have valid regex",
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
								Identities: []Identity{{Subject: ".*subject.*", Issuer: ".*issuer.*"}},
							},
						},
					},
				},
			},
		},
		{
			name:      "Should pass when identities is valid",
			expectErr: false,
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
		t.Run(test.name, func(t *testing.T) {
			err := test.policy.Validate(context.TODO())
			if test.expectErr {
				require.NotNil(t, err)
				require.EqualError(t, err, test.errorString)
			} else {
				require.Nil(t, err)
			}
		})
	}
}

func TestAWSKMSValidation(t *testing.T) {
	tests := []struct {
		name        string
		expectErr   bool
		errorString string
		kms         string
	}{
		{
			name:        "malformed, only 2 slashes ",
			expectErr:   true,
			errorString: "invalid value: awskms://1234abcd-12ab-34cd-56ef-1234567890ab: kms\nmalformed AWS KMS format, should be: 'awskms://$ENDPOINT/$KEYID'",
			kms:         "awskms://1234abcd-12ab-34cd-56ef-1234567890ab",
		},
		{
			name:        "fails with invalid host",
			expectErr:   true,
			errorString: "invalid value: awskms://localhost:::4566/alias/exampleAlias: kms\nmalformed endpoint: address localhost:::4566: too many colons in address",
			kms:         "awskms://localhost:::4566/alias/exampleAlias",
		},
		{
			name:        "fails with non-arn alias",
			expectErr:   true,
			errorString: "invalid value: awskms://localhost:4566/alias/exampleAlias: kms\nfailed to parse either key or alias arn: arn: invalid prefix",
			kms:         "awskms://localhost:4566/alias/exampleAlias",
		},
		{
			name:        "Should fail when arn is invalid",
			expectErr:   true,
			errorString: "invalid value: awskms://localhost:4566/arn:sonotvalid: kms\nfailed to parse either key or alias arn: arn: not enough sections",
			kms:         "awskms://localhost:4566/arn:sonotvalid",
		},
		{
			name: "works with valid arn key and endpoint",
			kms:  "awskms://localhost:4566/arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
		},
		{
			name: "works with valid arn key and no endpoint",
			kms:  "awskms:///arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
		},
		{
			name: "works with valid arn alias and endpoint",
			kms:  "awskms://localhost:4566/arn:aws:kms:us-east-2:111122223333:alias/ExampleAlias",
		},
		{
			name: "works with valid arn alias and no endpoint",
			kms:  "awskms:///arn:aws:kms:us-east-2:111122223333:alias/ExampleAlias",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			keyRef := KeyRef{KMS: test.kms}
			err := keyRef.Validate(context.TODO())
			if test.expectErr {
				require.NotNil(t, err)
				require.EqualError(t, err, test.errorString)
			} else {
				require.Nil(t, err)
			}
		})
	}

}
