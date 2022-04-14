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
	"fmt"
	"regexp"
	"strings"

	"github.com/sigstore/cosign/pkg/apis/utils"
	"knative.dev/pkg/apis"
)

// Validate implements apis.Validatable
func (policy *ClusterImagePolicy) Validate(ctx context.Context) *apis.FieldError {
	return policy.Spec.Validate(ctx).ViaField("spec")
}

func (spec *ClusterImagePolicySpec) Validate(ctx context.Context) (errors *apis.FieldError) {
	if len(spec.Images) == 0 {
		errors = errors.Also(apis.ErrMissingField("images"))
	}
	for i, image := range spec.Images {
		errors = errors.Also(image.Validate(ctx).ViaFieldIndex("images", i))
	}
	if len(spec.Authorities) == 0 {
		errors = errors.Also(apis.ErrMissingField("authorities"))
	}
	for i, authority := range spec.Authorities {
		errors = errors.Also(authority.Validate(ctx).ViaFieldIndex("authorities", i))
	}

	return
}

func (image *ImagePattern) Validate(ctx context.Context) *apis.FieldError {
	var errs *apis.FieldError
	if image.Regex != "" && image.Glob != "" {
		errs = errs.Also(apis.ErrMultipleOneOf("regex", "glob"))
	}

	if image.Regex == "" && image.Glob == "" {
		errs = errs.Also(apis.ErrMissingOneOf("regex", "glob"))
	}

	if image.Glob != "" {
		errs = errs.Also(ValidateGlob(image.Glob).ViaField("glob"))
	}

	if image.Regex != "" {
		errs = errs.Also(ValidateRegex(image.Regex).ViaField("regex"))
	}

	return errs
}

func (authority *Authority) Validate(ctx context.Context) *apis.FieldError {
	var errs *apis.FieldError
	if authority.Key == nil && authority.Keyless == nil {
		errs = errs.Also(apis.ErrMissingOneOf("key", "keyless"))
	}
	if authority.Key != nil && authority.Keyless != nil {
		errs = errs.Also(apis.ErrMultipleOneOf("key", "keyless"))
	}

	if authority.Key != nil {
		errs = errs.Also(authority.Key.Validate(ctx).ViaField("key"))
	}
	if authority.Keyless != nil {
		errs = errs.Also(authority.Keyless.Validate(ctx).ViaField("keyless"))
	}

	return errs
}

func (key *KeyRef) Validate(ctx context.Context) *apis.FieldError {
	var errs *apis.FieldError

	if key.Data == "" && key.KMS == "" && key.SecretRef == nil {
		errs = errs.Also(apis.ErrMissingOneOf("data", "kms", "secretref"))
	}

	if key.Data != "" {
		if key.KMS != "" || key.SecretRef != nil {
			errs = errs.Also(apis.ErrMultipleOneOf("data", "kms", "secretref"))
		}
		validPubkey := utils.IsValidKey([]byte(key.Data))
		if !validPubkey {
			errs = errs.Also(
				apis.ErrInvalidValue(key.Data, "data"),
			)
		}
	} else if key.KMS != "" && key.SecretRef != nil {
		errs = errs.Also(apis.ErrMultipleOneOf("data", "kms", "secretref"))
	}
	return errs
}

func (keyless *KeylessRef) Validate(ctx context.Context) *apis.FieldError {
	var errs *apis.FieldError
	if keyless.URL == nil && keyless.Identities == nil && keyless.CACert == nil {
		errs = errs.Also(apis.ErrMissingOneOf("url", "identities", "ca-cert"))
	}

	// TODO: Are these really mutually exclusive?
	if keyless.URL != nil && keyless.CACert != nil {
		errs = errs.Also(apis.ErrMultipleOneOf("url", "ca-cert"))
	}

	if keyless.Identities != nil && len(keyless.Identities) == 0 {
		errs = errs.Also(apis.ErrMissingField("identities"))
	}

	for i, identity := range keyless.Identities {
		errs = errs.Also(identity.Validate(ctx).ViaFieldIndex("identities", i))
	}
	return errs
}

func (identity *Identity) Validate(ctx context.Context) *apis.FieldError {
	var errs *apis.FieldError
	if identity.Issuer == "" && identity.Subject == "" {
		errs = errs.Also(apis.ErrMissingOneOf("issuer", "subject"))
	}
	if identity.Issuer != "" {
		errs = errs.Also(ValidateRegex(identity.Issuer).ViaField("issuer"))
	}
	if identity.Subject != "" {
		errs = errs.Also(ValidateRegex(identity.Subject).ViaField("subject"))
	}
	return errs
}

// ValidateGlob makes sure that if there's "*" specified it's the trailing
// character.
func ValidateGlob(glob string) *apis.FieldError {
	c := strings.Count(glob, "*")
	switch c {
	case 0:
		return nil
	case 1:
		if !strings.HasSuffix(glob, "*") {
			return apis.ErrInvalidValue(glob, apis.CurrentField, "glob match supports only * as a trailing character")
		}
	default:
		return apis.ErrInvalidValue(glob, apis.CurrentField, "glob match supports only a single * as a trailing character")
	}
	return nil
}

func ValidateRegex(regex string) *apis.FieldError {
	_, err := regexp.Compile(regex)
	if err != nil {
		return apis.ErrInvalidValue(regex, apis.CurrentField, fmt.Sprintf("regex is invalid: %v", err))
	}

	return nil
}
