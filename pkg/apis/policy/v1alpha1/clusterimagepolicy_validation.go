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
	"net"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/sigstore/cosign/pkg/apis/utils"
	"knative.dev/pkg/apis"
)

const awsKMSPrefix = "awskms://"

// Validate implements apis.Validatable
func (c *ClusterImagePolicy) Validate(ctx context.Context) *apis.FieldError {
	return c.Spec.Validate(ctx).ViaField("spec")
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
	errors = errors.Also(spec.Policy.Validate(ctx))

	return
}

func (image *ImagePattern) Validate(ctx context.Context) *apis.FieldError {
	var errs *apis.FieldError
	if image.Glob == "" {
		errs = errs.Also(apis.ErrMissingField("glob"))
	}

	errs = errs.Also(ValidateGlob(image.Glob).ViaField("glob"))

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

	for i, source := range authority.Sources {
		errs = errs.Also(source.Validate(ctx).ViaFieldIndex("source", i))
	}

	for _, att := range authority.Attestations {
		errs = errs.Also(att.Validate(ctx).ViaField("attestations"))
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
	if key.KMS != "" {
		if strings.HasPrefix(key.KMS, awsKMSPrefix) {
			errs = errs.Also(validateAWSKMS(key.KMS).ViaField("kms"))
		}
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

	if keyless.CACert != nil {
		errs = errs.Also(keyless.DeepCopy().CACert.Validate(ctx).ViaField("ca-cert"))
	}
	for i, identity := range keyless.Identities {
		errs = errs.Also(identity.Validate(ctx).ViaFieldIndex("identities", i))
	}
	return errs
}

func (source *Source) Validate(ctx context.Context) *apis.FieldError {
	var errs *apis.FieldError
	if source.OCI == "" {
		errs = errs.Also(apis.ErrMissingField("oci"))
	}

	if len(source.SignaturePullSecrets) > 0 {
		for i, secret := range source.SignaturePullSecrets {
			if secret.Name == "" {
				errs = errs.Also(apis.ErrMissingField("name")).ViaFieldIndex("signaturePullSecrets", i)
			}
		}
	}
	return errs
}

func (a *Attestation) Validate(ctx context.Context) *apis.FieldError {
	var errs *apis.FieldError
	if a.Name == "" {
		errs = errs.Also(apis.ErrMissingField("name"))
	}
	if a.PredicateType == "" {
		errs = errs.Also(apis.ErrMissingField("predicateType"))
	} else if a.PredicateType != "custom" && a.PredicateType != "slsaprovenance" && a.PredicateType != "spdx" && a.PredicateType != "spdxjson" && a.PredicateType != "cyclonedx" && a.PredicateType != "link" && a.PredicateType != "vuln" {
		// TODO(vaikas): The above should be using something like:
		// if _, ok := options.PredicateTypeMap[a.PrecicateType]; !ok {
		// But it causes an import loop. That refactor can be part of
		// another PR.
		errs = errs.Also(apis.ErrInvalidValue(a.PredicateType, "predicateType", "unsupported precicate type"))
	}
	errs = errs.Also(a.Policy.Validate(ctx).ViaField("policy"))
	return errs
}

func (p *Policy) Validate(ctx context.Context) *apis.FieldError {
	if p == nil {
		return nil
	}
	var errs *apis.FieldError
	if p.Type != "cue" {
		errs = errs.Also(apis.ErrInvalidValue(p.Type, "type", "only cue is supported at the moment"))
	}
	if p.Data == "" {
		errs = errs.Also(apis.ErrMissingField("data"))
	}
	// TODO(vaikas): How to validate the cue / rego bytes here (data).
	return errs
}

func (identity *Identity) Validate(ctx context.Context) *apis.FieldError {
	var errs *apis.FieldError
	if identity.Issuer == "" && identity.Subject == "" && identity.IssuerRegExp == "" && identity.SubjectRegExp == "" {
		errs = errs.Also(apis.ErrMissingField("issuer", "subject", "issuerRegExp", "subjectRegExp"))
	}
	if identity.Issuer != "" && identity.IssuerRegExp != "" {
		errs = errs.Also(apis.ErrMultipleOneOf("issuer", "issuerRegExp"))
	}
	if identity.Subject != "" && identity.SubjectRegExp != "" {
		errs = errs.Also(apis.ErrMultipleOneOf("subject", "subjectRegExp"))
	}
	if identity.IssuerRegExp != "" {
		errs = errs.Also(ValidateRegex(identity.IssuerRegExp).ViaField("issuerRegExp"))
	}
	if identity.SubjectRegExp != "" {
		errs = errs.Also(ValidateRegex(identity.SubjectRegExp).ViaField("subjectRegExp"))
	}
	return errs
}

// ValidateGlob glob compilation by testing against empty string
func ValidateGlob(glob string) *apis.FieldError {
	_, err := filepath.Match(glob, "")
	if err != nil {
		return apis.ErrInvalidValue(glob, apis.CurrentField, fmt.Sprintf("glob is invalid: %v", err))
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

// validateAWSKMS validates that the KMS conforms to AWS
// KMS format:
// awskms://$ENDPOINT/$KEYID
// Where:
// $ENDPOINT is optional
// $KEYID is either the key ARN or an alias ARN
// Reasoning for only supporting these formats is that other
// formats require additional configuration via ENV variables.
func validateAWSKMS(kms string) *apis.FieldError {
	parts := strings.Split(kms, "/")
	if len(parts) < 4 {
		return apis.ErrInvalidValue(kms, apis.CurrentField, "malformed AWS KMS format, should be: 'awskms://$ENDPOINT/$KEYID'")
	}
	endpoint := parts[2]
	// missing endpoint is fine, only validate if not empty
	if endpoint != "" {
		_, _, err := net.SplitHostPort(endpoint)
		if err != nil {
			return apis.ErrInvalidValue(kms, apis.CurrentField, fmt.Sprintf("malformed endpoint: %s", err))
		}
	}
	keyID := parts[3]
	arn, err := arn.Parse(keyID)
	if err != nil {
		return apis.ErrInvalidValue(kms, apis.CurrentField, fmt.Sprintf("failed to parse either key or alias arn: %s", err))
	}
	// Only support key or alias ARN.
	if arn.Resource != "key" && arn.Resource != "alias" {
		return apis.ErrInvalidValue(kms, apis.CurrentField, fmt.Sprintf("Got ARN: %+v Resource: %s", arn, arn.Resource))
	}
	return nil
}
