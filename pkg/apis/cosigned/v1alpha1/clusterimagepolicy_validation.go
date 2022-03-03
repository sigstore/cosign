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

	"knative.dev/pkg/apis"
)

// Validate implements apis.Validatable
func (policy *ClusterImagePolicy) Validate(ctx context.Context) *apis.FieldError {
	return policy.Spec.Validate(ctx).ViaField("spec")
}

func (spec *ClusterImagePolicySpec) Validate(ctx context.Context) (errors *apis.FieldError) {
	for i, image := range spec.Images {
		errors = errors.Also(image.Validate(ctx)).ViaFieldIndex("images", i)
	}
	return
}

func (image *ImagePattern) Validate(ctx context.Context) (errors *apis.FieldError) {
	if image.Regex != "" && image.Glob != "" {
		errors = errors.Also(apis.ErrMultipleOneOf("regex", "glob")).ViaField("images")
	}

	if image.Regex == "" && image.Glob == "" {
		errors = errors.Also(apis.ErrMissingOneOf("regex", "glob")).ViaField("images")
	}

	if len(image.Authorities) == 0 {
		errors = errors.Also(apis.ErrGeneric("At least one authority should be defined")).ViaField("authorities")
	}
	for i, authority := range image.Authorities {
		errors = errors.Also(authority.Validate(ctx)).ViaFieldIndex("authorities", i)
	}

	return
}

func (authority *Authority) Validate(ctx context.Context) (errors *apis.FieldError) {
	if authority.Key == nil && authority.Keyless == nil {
		return errors.Also(apis.ErrMissingOneOf("key", "keyless")).ViaField("authority")
	}
	if authority.Key != nil && authority.Keyless != nil {
		return errors.Also(apis.ErrMultipleOneOf("key", "keyless")).ViaField("authority")
	}

	if authority.Key != nil {
		errors = errors.Also(authority.Key.Validate(ctx)).ViaField("authority")
	}
	if authority.Keyless != nil {
		errors = errors.Also(authority.Keyless.Validate(ctx)).ViaField("authority")
	}

	return
}

func (key *KeyRef) Validate(ctx context.Context) (errors *apis.FieldError) {
	if key.Data == "" && key.KMS == "" && key.SecretRef == nil {
		return errors.Also(apis.ErrMissingOneOf("data", "kms", "secretref")).ViaField("key")
	}

	if key.Data != "" {
		if key.KMS != "" || key.SecretRef != nil {
			return errors.Also(apis.ErrMultipleOneOf("data", "kms", "secretref")).ViaField("key")
		}
	} else if key.KMS != "" && key.SecretRef != nil {
		return errors.Also(apis.ErrMultipleOneOf("data", "kms", "secretref")).ViaField("key")
	}
	return
}

func (keyless *KeylessRef) Validate(ctx context.Context) (errors *apis.FieldError) {
	if keyless.URL == nil && keyless.Identities == nil && keyless.CAKey == nil {
		return errors.Also(apis.ErrMissingOneOf("url", "identities", "ca-key")).ViaField("keyless")
	}

	if keyless.URL != nil {
		if keyless.CAKey != nil || keyless.Identities != nil {
			return errors.Also(apis.ErrMultipleOneOf("url", "identities", "ca-key")).ViaField("keyless")
		}
	} else if keyless.CAKey != nil && keyless.Identities != nil {
		return errors.Also(apis.ErrMultipleOneOf("url", "identities", "ca-key")).ViaField("keyless")
	}

	if keyless.Identities != nil && len(keyless.Identities) == 0 {
		return errors.Also(apis.ErrGeneric("At least one identity must be provided")).ViaField("keyless")
	}

	for i, identity := range keyless.Identities {
		errors = errors.Also(identity.Validate(ctx)).ViaFieldIndex("identities", i)
	}
	return
}

func (identity *Identity) Validate(ctx context.Context) (errors *apis.FieldError) {
	if identity.Issuer == "" && identity.Subject == "" {
		return apis.ErrMissingOneOf("issuer", "subject").ViaField("identity")
	}
	return
}
