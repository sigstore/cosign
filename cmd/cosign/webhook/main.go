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
	goflag "flag"
	"net"
	"net/http"
	"os"
	"strconv"

	flag "github.com/spf13/pflag"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/sigstore/cosign/pkg/cosign/kubernetes/webhook"
)

func main() {
	ctrl.SetLogger(zap.New(func(o *zap.Options) {
		o.Development = true
	}))

	var (
		metricsAddr        = net.ParseIP("127.0.0.1")
		metricsPort uint16 = 8080

		bindAddr        = net.ParseIP("0.0.0.0")
		bindPort uint16 = 8443

		tlsCertDirectory string
		secretKeyRef     string
	)

	klog.InitFlags(goflag.CommandLine)
	flags := flag.NewFlagSet("main", flag.ExitOnError)
	flags.AddGoFlagSet(goflag.CommandLine)
	flags.StringVar(&secretKeyRef, "secret-key-ref", "", "The secret that includes pub/private key pair")
	flags.IPVar(&metricsAddr, "metrics-address", metricsAddr, "The address the metric endpoint binds to.")
	flags.Uint16Var(&metricsPort, "metrics-port", metricsPort, "The port the metric endpoint binds to.")
	flags.IPVar(&bindAddr, "bind-address", bindAddr, ""+
		"The IP address on which to listen for the --secure-port port.")
	flags.Uint16Var(&bindPort, "secure-port", bindPort, "The port on which to serve HTTPS.")
	flags.StringVar(&tlsCertDirectory, "tls-cert-dir", tlsCertDirectory, "The directory where the TLS certs are located.")

	err := flags.Parse(os.Args[1:])
	if err != nil {
		klog.Error(err)
		os.Exit(1)
	}

	cosignedValidationFuncs := map[schema.GroupVersionKind]webhook.ValidationFunc{
		corev1.SchemeGroupVersion.WithKind("Pod"):          webhook.ValidateSignedResources,
		batchv1.SchemeGroupVersion.WithKind("Job"):         webhook.ValidateSignedResources,
		appsv1.SchemeGroupVersion.WithKind("Deployment"):   webhook.ValidateSignedResources,
		appsv1.SchemeGroupVersion.WithKind("StatefulSet"):  webhook.ValidateSignedResources,
		appsv1.SchemeGroupVersion.WithKind("ReplicateSet"): webhook.ValidateSignedResources,
		appsv1.SchemeGroupVersion.WithKind("DaemonSet"):    webhook.ValidateSignedResources,
	}

	cosignedValidationHook := webhook.NewFuncAdmissionValidator(webhook.Scheme, cosignedValidationFuncs, secretKeyRef)

	opts := ctrl.Options{
		Scheme:             webhook.Scheme,
		MetricsBindAddress: net.JoinHostPort(metricsAddr.String(), strconv.Itoa(int(metricsPort))),
		Host:               bindAddr.String(),
		Port:               int(bindPort),
		CertDir:            tlsCertDirectory,
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), opts)
	if err != nil {
		klog.Error(err, "Failed to create manager")
		os.Exit(1)
	}

	// Get the controller manager webhook server.
	webhookServer := mgr.GetWebhookServer()

	// Register the webhooks in the server.
	webhookServer.Register("/validations", cosignedValidationHook)

	// Add healthz and readyz handlers to webhook server. The controller-runtime AddHealthzCheck/AddReadyzCheck methods
	// are served via separate http server - better to serve these from the same webhook http server.
	webhookServer.WebhookMux.Handle("/readyz/", http.StripPrefix("/readyz/", &healthz.Handler{}))
	webhookServer.WebhookMux.Handle("/healthz/", http.StripPrefix("/healthz/", &healthz.Handler{}))

	klog.Info("Starting the webhook...")

	// Start the server by starting a previously-set-up manager
	if err := mgr.Start(context.Background()); err != nil {
		klog.Error(err)
		os.Exit(1)
	}
}
