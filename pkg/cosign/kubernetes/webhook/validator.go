//
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

package webhook

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	listersv1 "k8s.io/client-go/listers/core/v1"
	"knative.dev/pkg/apis"
	duckv1 "knative.dev/pkg/apis/duck/v1"
	secretinformer "knative.dev/pkg/injection/clients/namespacedkube/informers/core/v1/secret"
	"knative.dev/pkg/system"
)

type Validator struct {
	lister     listersv1.SecretLister
	secretName string
}

func NewValidator(ctx context.Context, secretName string) *Validator {
	return &Validator{
		lister:     secretinformer.Get(ctx).Lister(),
		secretName: secretName,
	}
}

// ValidatePodSpecable implements duckv1.PodSpecValidator
func (v *Validator) ValidatePodSpecable(ctx context.Context, wp *duckv1.WithPod) *apis.FieldError {
	return v.validatePodSpec(ctx, &wp.Spec.Template.Spec).ViaField("spec.template.spec")
}

// ValidatePod implements duckv1.PodValidator
func (v *Validator) ValidatePod(ctx context.Context, p *duckv1.Pod) *apis.FieldError {
	return v.validatePodSpec(ctx, &p.Spec).ViaField("spec")
}

func (v *Validator) validatePodSpec(ctx context.Context, ps *corev1.PodSpec) (errs *apis.FieldError) {
	s, err := v.lister.Secrets(system.Namespace()).Get(v.secretName)
	if err != nil {
		return apis.ErrGeneric(err.Error(), apis.CurrentField)
	}

	keys, kerr := getKeys(ctx, s.Data)
	if kerr != nil {
		return kerr
	}
	for i, c := range ps.InitContainers {
		if !valid(ctx, c.Image, keys) {
			errs = errs.Also(apis.ErrGeneric("invalid image signature", "image").ViaFieldIndex("initContainers", i))
		}
	}
	for i, c := range ps.Containers {
		if !valid(ctx, c.Image, keys) {
			errs = errs.Also(apis.ErrGeneric("invalid image signature", "image").ViaFieldIndex("containers", i))
		}
	}
	return errs
}
