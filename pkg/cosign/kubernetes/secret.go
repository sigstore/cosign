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

package kubernetes

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	kubernetesclient "github.com/GoogleContainerTools/skaffold/pkg/skaffold/kubernetes/client"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/pkg/cosign"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func KeyPairSecret(k8sRef string, pf cosign.PassFunc) error {
	namespace, name, err := parseRef(k8sRef)
	if err != nil {
		return err
	}
	// now, generate the key in memory
	keys, err := cosign.GenerateKeyPair(pf)
	if err != nil {
		return errors.Wrap(err, "generating key pair")
	}

	ctx := context.TODO()
	// create the client
	client, err := kubernetesclient.Client()
	if err != nil {
		return errors.Wrap(err, "new for config")
	}
	s, err := client.CoreV1().Secrets(namespace).Create(ctx, secret(keys, namespace, name), metav1.CreateOptions{})
	if err != nil {
		return errors.Wrapf(err, "creating secret %s in ns %s", name, namespace)
	}

	fmt.Fprintf(os.Stderr, "Successfully created secret %s in namespace %s\n", s.Name, s.Namespace)
	if err := ioutil.WriteFile("cosign.pub", keys.PublicBytes, 0600); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Public key written to cosign.pub")
	return nil
}

// creates a secret with the following data:
// * cosign.key
// * cosign.pub
// * cosign.password
func secret(keys *cosign.Keys, namespace, name string) *v1.Secret {
	return &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Data: map[string][]byte{
			"cosign.key":      keys.PrivateBytes,
			"cosign.pub":      keys.PublicBytes,
			"cosign.password": keys.Password(),
		},
	}
}

// the reference should be formatted as <namespace>/<secret name>
func parseRef(k8sRef string) (string, string, error) {
	s := strings.Split(k8sRef, "/")
	if len(s) != 2 {
		return "", "", errors.New("please format the k8s secret reference as <namespace>/<secret name>")
	}
	return s[0], s[1], nil
}
