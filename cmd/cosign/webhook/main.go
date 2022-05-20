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
	"log"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	batchv1beta1 "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	duckv1 "knative.dev/pkg/apis/duck/v1"
	"knative.dev/pkg/configmap"
	"knative.dev/pkg/controller"
	"knative.dev/pkg/injection/sharedmain"
	"knative.dev/pkg/logging"
	"knative.dev/pkg/signals"
	"knative.dev/pkg/webhook"
	"knative.dev/pkg/webhook/certificates"
	"knative.dev/pkg/webhook/resourcesemantics"
	"knative.dev/pkg/webhook/resourcesemantics/defaulting"
	"knative.dev/pkg/webhook/resourcesemantics/validation"
	"sigs.k8s.io/release-utils/version"

	"github.com/sigstore/cosign/pkg/apis/config"
	cwebhook "github.com/sigstore/cosign/pkg/cosign/kubernetes/webhook"
)

var secretName = flag.String("secret-name", "", "The name of the secret in the webhook's namespace that holds the public key for verification.")

// webhookName holds the name of the validating and mutating webhook
// configuration resources dispatching admission requests to policy-controller.
// It is also the name of the webhook which is injected by the controller
// with the resource types, namespace selectors, CABindle and service path.
// If this changes, you must also change:
//    ./config/500-webhook-configuration.yaml
//    https://github.com/sigstore/helm-charts/blob/main/charts/policy-controller/templates/webhook/webhook_mutating.yaml
//    https://github.com/sigstore/helm-charts/blob/main/charts/policy-controller/templates/webhook/webhook_validating.yaml
var webhookName = flag.String("webhook-name", "policy.sigstore.dev", "The name of the validating and mutating webhook configurations as well as the webhook name that is automatically configured, if exists, with different rules and client settings setting how the admission requests to be dispatched to policy-controller.")

func main() {
	opts := webhook.Options{
		ServiceName: "webhook",
		Port:        8443,
		SecretName:  "webhook-certs",
	}
	ctx := webhook.WithOptions(signals.NewContext(), opts)

	// Allow folks to configure the port the webhook serves on.
	flag.IntVar(&opts.Port, "secure-port", opts.Port, "The port on which to serve HTTPS.")

	v := version.GetVersionInfo()
	vJSON, _ := v.JSONString()
	log.Printf("%v", vJSON)
	// This calls flag.Parse()
	sharedmain.MainWithContext(ctx, "policy-controller",
		certificates.NewController,
		NewValidatingAdmissionController,
		NewMutatingAdmissionController,
	)
}

var types = map[schema.GroupVersionKind]resourcesemantics.GenericCRD{
	corev1.SchemeGroupVersion.WithKind("Pod"): &duckv1.Pod{},

	appsv1.SchemeGroupVersion.WithKind("ReplicaSet"):  &duckv1.WithPod{},
	appsv1.SchemeGroupVersion.WithKind("Deployment"):  &duckv1.WithPod{},
	appsv1.SchemeGroupVersion.WithKind("StatefulSet"): &duckv1.WithPod{},
	appsv1.SchemeGroupVersion.WithKind("DaemonSet"):   &duckv1.WithPod{},
	batchv1.SchemeGroupVersion.WithKind("Job"):        &duckv1.WithPod{},

	batchv1.SchemeGroupVersion.WithKind("CronJob"):      &duckv1.CronJob{},
	batchv1beta1.SchemeGroupVersion.WithKind("CronJob"): &duckv1.CronJob{},
}

func NewValidatingAdmissionController(ctx context.Context, cmw configmap.Watcher) *controller.Impl {
	// Decorate contexts with the current state of the config.
	store := config.NewStore(logging.FromContext(ctx).Named("config-store"))
	store.WatchConfigs(cmw)
	validator := cwebhook.NewValidator(ctx, *secretName)

	return validation.NewAdmissionController(ctx,
		// Name of the resource webhook.
		*webhookName,

		// The path on which to serve the webhook.
		"/validations",

		// The resources to validate.
		types,

		// A function that infuses the context passed to Validate/SetDefaults with custom metadata.
		func(ctx context.Context) context.Context {
			ctx = store.ToContext(ctx)
			ctx = duckv1.WithPodValidator(ctx, validator.ValidatePod)
			ctx = duckv1.WithPodSpecValidator(ctx, validator.ValidatePodSpecable)
			ctx = duckv1.WithCronJobValidator(ctx, validator.ValidateCronJob)
			return ctx
		},

		// Whether to disallow unknown fields.
		// We pass false because we're using partial schemas.
		false,

		// Extra validating callbacks to be applied to resources.
		nil,
	)
}

func NewMutatingAdmissionController(ctx context.Context, cmw configmap.Watcher) *controller.Impl {
	validator := cwebhook.NewValidator(ctx, *secretName)

	return defaulting.NewAdmissionController(ctx,
		// Name of the resource webhook.
		*webhookName,

		// The path on which to serve the webhook.
		"/mutations",

		// The resources to validate.
		types,

		// A function that infuses the context passed to Validate/SetDefaults with custom metadata.
		func(ctx context.Context) context.Context {
			ctx = duckv1.WithPodDefaulter(ctx, validator.ResolvePod)
			ctx = duckv1.WithPodSpecDefaulter(ctx, validator.ResolvePodSpecable)
			ctx = duckv1.WithCronJobDefaulter(ctx, validator.ResolveCronJob)
			return ctx
		},

		// Whether to disallow unknown fields.
		// We pass false because we're using partial schemas.
		false,
	)
}
