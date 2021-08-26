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
	"fmt"
	"os"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type ClientOptions struct {
	// KubeconfigPath is a filename for a kubeconfig file to contact the Kubernetes API server with.
	// If it is not set, the in cluster config is used.
	KubeconfigPath string

	scheme *runtime.Scheme
}

func NewClientOptions(scheme *runtime.Scheme) *ClientOptions {
	return &ClientOptions{scheme: scheme}
}

func (o *ClientOptions) NewDynamicClient() (client.Client, error) {
	var kubeconfig *rest.Config
	var err error
	if len(o.KubeconfigPath) > 0 {
		loadingRules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: o.KubeconfigPath}
		loader := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, &clientcmd.ConfigOverrides{})
		kubeconfig, err = loader.ClientConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to load kubeconfig at %q: %v", o.KubeconfigPath, err)
		}
	} else {
		kubeconfig, err = rest.InClusterConfig()
		if err != nil {
			return nil, err
		}
	}
	dynamicClient, err := client.New(kubeconfig, client.Options{Scheme: o.scheme})
	if err != nil {
		return nil, fmt.Errorf("failed to create dynamic client %w", err)
	}

	return dynamicClient, nil
}

// Create a REST config for talking to a Kubernetes API server.
// The order of precedence is defined as follows:
// 1. If `kubeconfigPath` is set explicitly, use it to load the config.
// 2. If `KUBECONFIG` env var is set, use it to load the config.
// 3. Assumes in-cluster, and return in-cluster config.
// 4. $HOME/.kube/config if exists
func GetRestConfig(kubeconfigPath string) (*rest.Config, error) {
	if kubeconfigPath == "" {
		kubeconfigPath = os.Getenv(clientcmd.RecommendedConfigPathEnvVar)
	}

	if kubeconfigPath != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	}

	if config, err := rest.InClusterConfig(); err == nil {
		return config, nil
	}

	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		clientcmd.NewDefaultClientConfigLoadingRules(),
		nil).ClientConfig()
}
