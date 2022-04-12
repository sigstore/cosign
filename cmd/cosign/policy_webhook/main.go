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
	"knative.dev/pkg/webhook/resourcesemantics/defaulting"
	"knative.dev/pkg/webhook/resourcesemantics/validation"
	"sigs.k8s.io/release-utils/version"

	"github.com/sigstore/cosign/pkg/apis/cosigned/v1alpha1"
	"github.com/sigstore/cosign/pkg/reconciler/clusterimagepolicy"

	// Register the provider-specific plugins
	_ "github.com/sigstore/sigstore/pkg/signature/kms/aws"
	_ "github.com/sigstore/sigstore/pkg/signature/kms/azure"
	_ "github.com/sigstore/sigstore/pkg/signature/kms/gcp"
	_ "github.com/sigstore/sigstore/pkg/signature/kms/hashivault"
	// TODO(mattmoor): Not sure why this is in the final binary...
	// _ "github.com/sigstore/sigstore/pkg/signature/kms/fake"
)

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
	)
}

func NewPolicyValidatingAdmissionController(ctx context.Context, cmw configmap.Watcher) *controller.Impl {
	return validation.NewAdmissionController(
		ctx,
		"validating.clusterimagepolicy.sigstore.dev",
		"/validating",
		map[schema.GroupVersionKind]resourcesemantics.GenericCRD{
			v1alpha1.SchemeGroupVersion.WithKind("ClusterImagePolicy"): &v1alpha1.ClusterImagePolicy{},
		},
		func(ctx context.Context) context.Context {
			return ctx
		},
		true,
	)
}

func NewPolicyMutatingAdmissionController(ctx context.Context, cmw configmap.Watcher) *controller.Impl {
	return defaulting.NewAdmissionController(
		ctx,
		"defaulting.clusterimagepolicy.sigstore.dev",
		"/defaulting",
		map[schema.GroupVersionKind]resourcesemantics.GenericCRD{
			v1alpha1.SchemeGroupVersion.WithKind("ClusterImagePolicy"): &v1alpha1.ClusterImagePolicy{},
		},
		func(ctx context.Context) context.Context {
			return ctx
		},
		true,
	)
}
