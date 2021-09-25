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
	"errors"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/oci"
	"github.com/sigstore/cosign/pkg/oci/static"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"knative.dev/pkg/apis"
	fakesecret "knative.dev/pkg/injection/clients/namespacedkube/informers/core/v1/secret/fake"
	rtesting "knative.dev/pkg/reconciler/testing"
	"knative.dev/pkg/system"
)

func TestValidatePodSpec(t *testing.T) {
	tag := name.MustParseReference("gcr.io/distroless/static:nonroot")
	// Resolved via crane digest on 2021/09/25
	digest := name.MustParseReference("gcr.io/distroless/static:nonroot@sha256:be5d77c62dbe7fedfb0a4e5ec2f91078080800ab1f18358e5f31fcc8faa023c4")

	ctx, _ := rtesting.SetupFakeContext(t)
	si := fakesecret.Get(ctx)

	secretName := "blah"

	si.Informer().GetIndexer().Add(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: system.Namespace(),
			Name:      secretName,
		},
		Data: map[string][]byte{
			// Random public key (cosign generate-key-pair) 2021-09-25
			"cosign.pub": []byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEapTW568kniCbL0OXBFIhuhOboeox
UoJou2P8sbDxpLiE/v3yLw1/jyOrCPWYHWFXnyyeGlkgSVefG54tNoK7Uw==
-----END PUBLIC KEY-----
`),
		},
	})

	v := NewValidator(ctx, secretName)

	cvs := cosignVerifySignatures
	defer func() {
		cosignVerifySignatures = cvs
	}()
	// Let's just say that everything is verified.
	pass := func(ctx context.Context, signedImgRef name.Reference, co *cosign.CheckOpts) (checkedSignatures []oci.Signature, bundleVerified bool, err error) {
		sig, err := static.NewSignature(nil, "")
		if err != nil {
			return nil, false, err
		}
		return []oci.Signature{sig}, true, nil
	}
	// Let's just say that everything is verified.
	fail := func(ctx context.Context, signedImgRef name.Reference, co *cosign.CheckOpts) (checkedSignatures []oci.Signature, bundleVerified bool, err error) {
		return nil, false, errors.New("bad signature")
	}

	tests := []struct {
		name string
		ps   *corev1.PodSpec
		want *apis.FieldError
		cvs  func(context.Context, name.Reference, *cosign.CheckOpts) ([]oci.Signature, bool, error)
	}{{
		name: "simple, no error",
		ps: &corev1.PodSpec{
			InitContainers: []corev1.Container{{
				Name:  "setup-stuff",
				Image: digest.String(),
			}},
			Containers: []corev1.Container{{
				Name:  "user-container",
				Image: digest.String(),
			}},
		},
		cvs: pass,
	}, {
		name: "bad reference",
		ps: &corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "user-container",
				Image: "in@valid",
			}},
		},
		want: &apis.FieldError{
			Message: `could not parse reference: in@valid`,
			Paths:   []string{"containers[0].image"},
		},
		cvs: fail,
	}, {
		name: "not digest",
		ps: &corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "user-container",
				Image: tag.String(),
			}},
		},
		want: &apis.FieldError{
			Message: `invalid value: gcr.io/distroless/static:nonroot must be an image digest`,
			Paths:   []string{"containers[0].image"},
		},
		cvs: fail,
	}, {
		name: "bad signature",
		ps: &corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "user-container",
				Image: digest.String(),
			}},
		},
		want: &apis.FieldError{
			Message: `invalid image signature`,
			Paths:   []string{"containers[0].image"},
		},
		cvs: fail,
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cosignVerifySignatures = test.cvs
			got := v.validatePodSpec(context.Background(), test.ps)
			if (got != nil) != (test.want != nil) {
				t.Errorf("validatePodSpec() = %v, wanted %v", got, test.want)
			} else if got != nil && got.Error() != test.want.Error() {
				t.Errorf("validatePodSpec() = %v, wanted %v", got, test.want)
			}
		})
	}
}
