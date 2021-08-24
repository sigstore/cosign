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
	"crypto/ecdsa"
	"fmt"
	"net/http"

	admissionv1 "k8s.io/api/admission/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/sigstore/cosign/pkg/cosign/kubernetes"
)

var (
	Scheme = runtime.NewScheme()
)

func init() { //nolint:gochecknoinits
	utilruntime.Must(corev1.AddToScheme(Scheme))
	utilruntime.Must(appsv1.AddToScheme(Scheme))
	utilruntime.Must(batchv1.AddToScheme(Scheme))
}

type funcAdmissionValidator struct {
	regularDecoder      runtime.Decoder
	unstructuredDecoder runtime.Decoder
	apiReader           client.Reader
	validations         map[schema.GroupVersionKind]ValidationFuncs
	scheme              *runtime.Scheme
	secretKeyRef        string
}

func NewFuncAdmissionValidator(scheme *runtime.Scheme, dynamicClient client.Client, fns map[schema.GroupVersionKind]ValidationFuncs, secretKeyRef string) *webhook.Admission {
	factory := serializer.NewCodecFactory(scheme)
	return &webhook.Admission{
		Handler: &funcAdmissionValidator{
			regularDecoder:      factory.UniversalDeserializer(),
			unstructuredDecoder: unstructured.UnstructuredJSONScheme,
			apiReader:           dynamicClient,
			scheme:              scheme,
			validations:         fns,
			secretKeyRef:        secretKeyRef,
		},
	}
}

type ValidationFuncs struct {
	ValidateCreate ValidationCreateFunc
	ValidateUpdate ValidationUpdateFunc
}

type ValidationCreateFunc func(newObj runtime.Object, apiReader client.Reader, keys []*ecdsa.PublicKey) field.ErrorList
type ValidationUpdateFunc func(newObj runtime.Object, oldObj runtime.Object, apiReader client.Reader, keys []*ecdsa.PublicKey) field.ErrorList

func (c *funcAdmissionValidator) Handle(_ context.Context, admissionSpec admission.Request) admission.Response {
	var (
		newObj, oldObj runtime.Object
		gvk            *schema.GroupVersionKind
		err            error
	)

	decoder := c.regularDecoder
	if len(admissionSpec.Object.Raw) > 0 {
		newObj, gvk, err = decoder.Decode(admissionSpec.Object.Raw, nil, nil)
		if err != nil {
			return admission.Response{
				AdmissionResponse: admissionv1.AdmissionResponse{
					Allowed: false,
					Result: &metav1.Status{
						Status:  metav1.StatusFailure,
						Code:    http.StatusInternalServerError,
						Reason:  metav1.StatusReasonInternalError,
						Message: fmt.Sprintf("Failed to decode object: %v", err),
					},
				},
			}
		}
	}

	if len(admissionSpec.OldObject.Raw) > 0 {
		oldObj, gvk, err = decoder.Decode(admissionSpec.OldObject.Raw, nil, nil)
		if err != nil {
			return admission.Response{
				AdmissionResponse: admissionv1.AdmissionResponse{
					Allowed: false,
					Result: &metav1.Status{
						Status:  metav1.StatusFailure,
						Code:    http.StatusInternalServerError,
						Reason:  metav1.StatusReasonInternalError,
						Message: fmt.Sprintf("Failed to decode object: %v", err),
					},
				},
			}
		}
	}

	cfg, err := kubernetes.GetKeyPairSecret(context.Background(), c.secretKeyRef)
	if err != nil {
		return admission.Response{
			AdmissionResponse: admissionv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Status:  metav1.StatusFailure,
					Code:    http.StatusInternalServerError,
					Reason:  metav1.StatusReasonInternalError,
					Message: err.Error(),
				},
			},
		}
	}
	if cfg == nil {
		return admission.Response{
			AdmissionResponse: admissionv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Status:  metav1.StatusFailure,
					Code:    http.StatusInternalServerError,
					Reason:  metav1.StatusReasonInternalError,
					Message: "no keys configured",
				},
			},
		}
	}

	validateFuncs, ok := c.validations[*gvk]
	if !ok {
		return admission.Response{
			AdmissionResponse: admissionv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Status:  metav1.StatusFailure,
					Code:    http.StatusInternalServerError,
					Reason:  metav1.StatusReasonInternalError,
					Message: fmt.Sprintf("No validation functions registered for GVK: %v", gvk.String()),
				},
			},
		}
	}

	var validationErrs field.ErrorList
	keys := getKeys(cfg.Data)

	switch admissionSpec.Operation {
	case admissionv1.Create:
		if validateFuncs.ValidateCreate != nil {
			validationErrs = validateFuncs.ValidateCreate(newObj, c.apiReader, keys)
		}
	case admissionv1.Update:
		if validateFuncs.ValidateUpdate != nil {
			validationErrs = validateFuncs.ValidateUpdate(newObj, oldObj, c.apiReader, keys)
		}
	default:
		return admission.Response{
			AdmissionResponse: admissionv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Status:  metav1.StatusFailure,
					Code:    http.StatusBadRequest,
					Reason:  metav1.StatusReasonBadRequest,
					Message: fmt.Sprintf("Invalid admission operation: %s", admissionSpec.Operation),
				},
			},
		}
	}

	if err := validationErrs.ToAggregate(); err != nil {
		return admission.Response{
			AdmissionResponse: admissionv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Status:  metav1.StatusFailure,
					Code:    http.StatusNotAcceptable,
					Reason:  metav1.StatusReasonNotAcceptable,
					Message: err.Error(),
				},
			},
		}
	}

	return admission.Response{
		AdmissionResponse: admissionv1.AdmissionResponse{
			Allowed: true,
		},
	}
}
