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

package cli

import (
	"context"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/kubernetes"
	"github.com/sigstore/sigstore/pkg/kms"
	"github.com/sigstore/sigstore/pkg/signature"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func loadKey(keyPath string, pf cosign.PassFunc) (signature.ECDSASignerVerifier, error) {
	kb, err := ioutil.ReadFile(filepath.Clean(keyPath))
	if err != nil {
		return signature.ECDSASignerVerifier{}, err
	}
	pass, err := pf(false)
	if err != nil {
		return signature.ECDSASignerVerifier{}, err
	}
	return cosign.LoadECDSAPrivateKey(kb, pass)
}

func signerFromKeyRef(ctx context.Context, keyRef string, pf cosign.PassFunc) (signature.Signer, error) {
	return signerVerifierFromKeyRef(ctx, keyRef, pf)
}

func signerVerifierFromKeyRef(ctx context.Context, keyRef string, pf cosign.PassFunc) (signature.SignerVerifier, error) {
	for prefix := range kms.ProvidersMux().Providers() {
		if strings.HasPrefix(keyRef, prefix) {
			return kms.Get(ctx, keyRef)
		}
	}

	s := strings.Split(keyRef, "/") // <namespace>/<secret>
	if len(s) == 2 {
		namespace, name := s[0], s[1]
		// create the k8s client
		client, err := kubernetes.Client()
		if err != nil {
			return nil, errors.Wrap(err, "new for config")
		}

		var s *v1.Secret
		if s, err = client.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{}); err != nil {
			return nil, errors.Wrap(err, "checking if secret exists")
		} else {
			return cosign.LoadECDSAPrivateKey(s.Data["cosign.key"], s.Data["cosign.password"])
		}
	}

	return loadKey(keyRef, pf)
}

func publicKeyFromKeyRef(ctx context.Context, keyRef string) (cosign.PublicKey, error) {
	return cosign.LoadPublicKey(ctx, keyRef)
}
