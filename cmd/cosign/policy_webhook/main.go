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

	"k8s.io/apimachinery/pkg/runtime/schema"
	"knative.dev/pkg/configmap"
	"knative.dev/pkg/controller"
	"knative.dev/pkg/injection/sharedmain"
	"knative.dev/pkg/signals"
	"knative.dev/pkg/webhook"
	"knative.dev/pkg/webhook/certificates"
	"knative.dev/pkg/webhook/resourcesemantics"
	"knative.dev/pkg/webhook/resourcesemantics/conversion"
	"knative.dev/pkg/webhook/resourcesemantics/defaulting"
	"knative.dev/pkg/webhook/resourcesemantics/validation"
	"sigs.k8s.io/release-utils/version"

	"github.com/sigstore/cosign/pkg/apis/cosigned"
	"github.com/sigstore/cosign/pkg/apis/cosigned/v1alpha1"
	"github.com/sigstore/cosign/pkg/apis/cosigned/v1beta1"
	"github.com/sigstore/cosign/pkg/reconciler/clusterimagepolicy"

	// Register the provider-specific plugins
	_ "github.com/sigstore/sigstore/pkg/signature/kms/aws"
	_ "github.com/sigstore/sigstore/pkg/signature/kms/azure"
	_ "github.com/sigstore/sigstore/pkg/signature/kms/gcp"
	_ "github.com/sigstore/sigstore/pkg/signature/kms/hashivault"
)

var (
	// mutatingWebhookName holds the name of the mutating webhook configuration
	// resource dispatching admission requests to policy-webhook.
	// It is also the name of the webhook which is injected by the controller
	// with the resource types, namespace selectors, CABindle and service path.
	// If this changes, you must also change:
	//    ./config/501-policy-webhook-configurations.yaml
	//    https://github.com/sigstore/helm-charts/blob/main/charts/cosigned/templates/policy-webhook/policy_webhook_configurations.yaml
	mutatingWebhookName = flag.String("mutating-webhook-name", "defaulting.clusterimagepolicy.sigstore.dev", "The name of the mutating webhook configuration as well as the webhook name that is automatically configured, if exists, with different rules and client settings setting how the admission requests to be dispatched to policy-webhook.")
	// validatingWebhookName holds the name of the validating webhook configuration
	// resource dispatching admission requests to policy-webhook.
	// It is also the name of the webhook which is injected by the controller
	// with the resource types, namespace selectors, CABindle and service path.
	// If this changes, you must also change:
	//    ./config/501-policy-webhook-configurations.yaml
	//    https://github.com/sigstore/helm-charts/blob/main/charts/cosigned/templates/policy-webhook/policy_webhook_configurations.yaml
	validatingWebhookName = flag.String("validating-webhook-name", "validating.clusterimagepolicy.sigstore.dev", "The name of the validating webhook configuration as well as the webhook name that is automatically configured, if exists, with different rules and client settings setting how the admission requests to be dispatched to policy-webhook.")
)

var types = map[schema.GroupVersionKind]resourcesemantics.GenericCRD{
	// v1alpha1
	v1alpha1.SchemeGroupVersion.WithKind("ClusterImagePolicy"): &v1alpha1.ClusterImagePolicy{},
	// v1beta1
	v1beta1.SchemeGroupVersion.WithKind("ClusterImagePolicy"): &v1beta1.ClusterImagePolicy{},
}

func main() {
	opts := webhook.Options{
		ServiceName: "policy-webhook",
		Port:        8443,
		SecretName:  "policy-webhook-certs",
	}
	ctx := webhook.WithOptions(signals.NewContext(), opts)

	// Allow folks to configure the port the webhook serves on.
	flag.IntVar(&opts.Port, "secure-port", opts.Port, "The port on which to serve HTTPS.")

	v := version.GetVersionInfo()
	vJSON, _ := v.JSONString()
	log.Printf("%v", vJSON)
	// This calls flag.Parse()
	sharedmain.MainWithContext(ctx, "clusterimagepolicy",
		certificates.NewController,
		clusterimagepolicy.NewController,
		NewPolicyValidatingAdmissionController,
		NewPolicyMutatingAdmissionController,
		newConversionController,
	)
}

func NewPolicyValidatingAdmissionController(ctx context.Context, cmw configmap.Watcher) *controller.Impl {
	return validation.NewAdmissionController(
		ctx,
		*validatingWebhookName,
		"/validating",
		types,
		func(ctx context.Context) context.Context {
			return ctx
		},
		true,
	)
}

func NewPolicyMutatingAdmissionController(ctx context.Context, cmw configmap.Watcher) *controller.Impl {
	return defaulting.NewAdmissionController(
		ctx,
		*mutatingWebhookName,
		"/defaulting",
		types,
		func(ctx context.Context) context.Context {
			return ctx
		},
		true,
	)
}

func newConversionController(ctx context.Context, cmw configmap.Watcher) *controller.Impl {
	// nolint: revive
	var (
		v1alpha1GroupVersion = v1alpha1.SchemeGroupVersion.Version
		v1beta1GroupVersion  = v1beta1.SchemeGroupVersion.Version
	)

	return conversion.NewConversionController(ctx,
		// The path on which to serve the webhook
		"/resource-conversion",

		// Specify the types of custom resource definitions that should be converted
		map[schema.GroupKind]conversion.GroupKindConversion{
			v1beta1.Kind("ClusterImagePolicy"): {
				DefinitionName: cosigned.ClusterImagePolicyResource.String(),
				HubVersion:     v1alpha1GroupVersion,
				Zygotes: map[string]conversion.ConvertibleObject{
					v1alpha1GroupVersion: &v1alpha1.ClusterImagePolicy{},
					v1beta1GroupVersion:  &v1beta1.ClusterImagePolicy{},
				},
			},
		},

		// A function that infuses the context passed to ConvertTo/ConvertFrom/SetDefaults with custom metadata
		func(ctx context.Context) context.Context {
			return ctx
		},
	)
}
