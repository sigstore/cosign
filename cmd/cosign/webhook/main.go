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

package main

import (
	"context"
	"flag"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	duckv1 "knative.dev/pkg/apis/duck/v1"
	"knative.dev/pkg/configmap"
	"knative.dev/pkg/controller"
	"knative.dev/pkg/injection/sharedmain"
	"knative.dev/pkg/signals"
	"knative.dev/pkg/webhook"
	"knative.dev/pkg/webhook/certificates"
	"knative.dev/pkg/webhook/resourcesemantics"
	"knative.dev/pkg/webhook/resourcesemantics/validation"

	cwebhook "github.com/sigstore/cosign/pkg/cosign/kubernetes/webhook"
)

var secretName = flag.String("secret-name", "", "The name of the secret in the webhook's namespace.")

func main() {
	ctx := webhook.WithOptions(signals.NewContext(), webhook.Options{
		ServiceName: "webhook",
		Port:        8443,
		SecretName:  "webhook-certs",
	})

	// This calls flag.Parse()
	sharedmain.MainWithContext(ctx, "cosigned",
		certificates.NewController,
		NewValidatingAdmissionController,
	)
}

func NewValidatingAdmissionController(ctx context.Context, cmw configmap.Watcher) *controller.Impl {
	validator := cwebhook.NewValidator(ctx, *secretName)

	return validation.NewAdmissionController(ctx,
		// Name of the resource webhook.
		"cosigned.sigstore.dev",

		// The path on which to serve the webhook.
		"/validations",

		// The resources to validate.
		map[schema.GroupVersionKind]resourcesemantics.GenericCRD{
			corev1.SchemeGroupVersion.WithKind("Pod"): &duckv1.Pod{},

			appsv1.SchemeGroupVersion.WithKind("ReplicaSet"):  &duckv1.WithPod{},
			appsv1.SchemeGroupVersion.WithKind("Deployment"):  &duckv1.WithPod{},
			appsv1.SchemeGroupVersion.WithKind("StatefulSet"): &duckv1.WithPod{},
			appsv1.SchemeGroupVersion.WithKind("DaemonSet"):   &duckv1.WithPod{},
			batchv1.SchemeGroupVersion.WithKind("Job"):        &duckv1.WithPod{},
		},

		// A function that infuses the context passed to Validate/SetDefaults with custom metadata.
		func(ctx context.Context) context.Context {
			ctx = duckv1.WithPodValidator(ctx, validator.ValidatePod)
			ctx = duckv1.WithPodSpecValidator(ctx, validator.ValidatePodSpecable)
			return ctx
		},

		// Whether to disallow unknown fields.
		// We pass false because we're using partial schemas.
		false,

		// Extra validating callbacks to be applied to resources.
		nil,
	)
}
