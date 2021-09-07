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
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/sigstore/pkg/signature"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
)

var (
	log = ctrl.Log.WithName("cosigned")
)

func ValidateSignedResources(obj runtime.Object, keys []*ecdsa.PublicKey) field.ErrorList {
	containers, err := getContainers(obj)
	if err != nil {
		return field.ErrorList{field.InternalError(field.NewPath(""), err)}
	}

	return validateSignedContainerImages(containers, keys)
}

func validateSignedContainerImages(containers []corev1.Container, keys []*ecdsa.PublicKey) field.ErrorList {
	var allErrs field.ErrorList

	containersRefPath := field.NewPath("spec").Child("containers")

	for _, c := range containers {
		if !valid(c.Image, keys) {
			allErrs = append(allErrs, field.Invalid(containersRefPath, c.Image, "invalid image signature"))
		}
	}

	return allErrs
}

func getContainers(decoded runtime.Object) ([]corev1.Container, error) {
	var (
		d   *appsv1.Deployment
		rs  *appsv1.ReplicaSet
		ss  *appsv1.StatefulSet
		ds  *appsv1.DaemonSet
		job *batchv1.Job
		pod *corev1.Pod
	)
	containers := make([]corev1.Container, 0)
	switch obj := decoded.(type) {
	case *appsv1.Deployment:
		d = obj
		containers = append(containers, d.Spec.Template.Spec.Containers...)
		containers = append(containers, d.Spec.Template.Spec.InitContainers...)
	case *appsv1.DaemonSet:
		ds = obj
		containers = append(containers, ds.Spec.Template.Spec.Containers...)
		containers = append(containers, ds.Spec.Template.Spec.InitContainers...)
	case *appsv1.ReplicaSet:
		rs = obj
		containers = append(containers, rs.Spec.Template.Spec.Containers...)
		containers = append(containers, rs.Spec.Template.Spec.InitContainers...)
	case *appsv1.StatefulSet:
		ss = obj
		containers = append(containers, ss.Spec.Template.Spec.Containers...)
		containers = append(containers, ss.Spec.Template.Spec.InitContainers...)
	case *batchv1.Job:
		job = obj
		containers = append(containers, job.Spec.Template.Spec.Containers...)
		containers = append(containers, job.Spec.Template.Spec.InitContainers...)
	case *corev1.Pod:
		pod = obj
		containers = append(containers, pod.Spec.Containers...)
		containers = append(containers, pod.Spec.InitContainers...)
	default:
		return containers, fmt.Errorf("can only validate pod types")
	}

	return containers, nil
}

func valid(img string, keys []*ecdsa.PublicKey) bool {
	for _, k := range keys {
		sps, err := validSignatures(context.Background(), img, k)
		if err != nil {
			return false
		}
		if len(sps) > 0 {
			return true
		}
	}
	return false
}

func validSignatures(ctx context.Context, img string, key *ecdsa.PublicKey) ([]cosign.SignedPayload, error) {
	ref, err := name.ParseReference(img)
	if err != nil {
		return nil, err
	}

	ecdsaVerifier, err := signature.LoadECDSAVerifier(key, crypto.SHA256)
	if err != nil {
		return nil, err
	}

	return cosign.Verify(ctx, ref, &cosign.CheckOpts{
		RootCerts:     fulcio.GetRoots(),
		SigVerifier:   ecdsaVerifier,
		ClaimVerifier: cosign.SimpleClaimVerifier,
	})
}

func getKeys(cfg map[string][]byte) []*ecdsa.PublicKey {
	keys := []*ecdsa.PublicKey{}

	pems := parsePems(cfg["cosign.pub"])
	for _, p := range pems {
		// TODO: (@dlorenc) check header
		key, err := x509.ParsePKIXPublicKey(p.Bytes)
		if err != nil {
			log.Error(err, "parsing key", "cosign.pub", p)
		}
		keys = append(keys, key.(*ecdsa.PublicKey))
	}
	return keys
}

func parsePems(b []byte) []*pem.Block {
	p, rest := pem.Decode(b)
	if p == nil {
		return nil
	}
	pems := []*pem.Block{p}

	if rest != nil {
		return append(pems, parsePems(rest)...)
	}
	return pems
}
