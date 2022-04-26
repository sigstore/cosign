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
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-containerregistry/pkg/authn/k8schain"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/pkg/apis/config"
	"github.com/sigstore/cosign/pkg/apis/cosigned/v1alpha1"
	"github.com/sigstore/cosign/pkg/cosign"
	webhookcip "github.com/sigstore/cosign/pkg/cosign/kubernetes/webhook/clusterimagepolicy"
	"github.com/sigstore/cosign/pkg/oci"
	"github.com/sigstore/cosign/pkg/oci/remote"
	"github.com/sigstore/cosign/pkg/oci/static"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"knative.dev/pkg/apis"
	duckv1 "knative.dev/pkg/apis/duck/v1"
	fakekube "knative.dev/pkg/client/injection/kube/client/fake"
	fakesecret "knative.dev/pkg/injection/clients/namespacedkube/informers/core/v1/secret/fake"
	rtesting "knative.dev/pkg/reconciler/testing"
	"knative.dev/pkg/system"
)

const (
	fulcioRootCert = "-----BEGIN CERTIFICATE-----\nMIICNzCCAd2gAwIBAgITPLBoBQhl1hqFND9S+SGWbfzaRTAKBggqhkjOPQQDAjBo\nMQswCQYDVQQGEwJVSzESMBAGA1UECBMJV2lsdHNoaXJlMRMwEQYDVQQHEwpDaGlw\ncGVuaGFtMQ8wDQYDVQQKEwZSZWRIYXQxDDAKBgNVBAsTA0NUTzERMA8GA1UEAxMI\ndGVzdGNlcnQwHhcNMjEwMzEyMjMyNDQ5WhcNMzEwMjI4MjMyNDQ5WjBoMQswCQYD\nVQQGEwJVSzESMBAGA1UECBMJV2lsdHNoaXJlMRMwEQYDVQQHEwpDaGlwcGVuaGFt\nMQ8wDQYDVQQKEwZSZWRIYXQxDDAKBgNVBAsTA0NUTzERMA8GA1UEAxMIdGVzdGNl\ncnQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQRn+Alyof6xP3GQClSwgV0NFuY\nYEwmKP/WLWr/LwB6LUYzt5v49RlqG83KuaJSpeOj7G7MVABdpIZYWwqAiZV3o2Yw\nZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBATAdBgNVHQ4EFgQU\nT8Jwm6JuVb0dsiuHUROiHOOVHVkwHwYDVR0jBBgwFoAUT8Jwm6JuVb0dsiuHUROi\nHOOVHVkwCgYIKoZIzj0EAwIDSAAwRQIhAJkNZmP6sKA+8EebRXFkBa9DPjacBpTc\nOljJotvKidRhAiAuNrIazKEw2G4dw8x1z6EYk9G+7fJP5m93bjm/JfMBtA==\n-----END CERTIFICATE-----"
	rekorResponse  = "bad response"

	// Random public key (cosign generate-key-pair) 2022-03-18
	authorityKeyCosignPubString = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENAyijLvRu5QpCPp2uOj8C79ZW1VJ
SID/4H61ZiRzN4nqONzp+ZF22qQTk3MFO3D0/ZKmWHAosIf2pf2GHH7myA==
-----END PUBLIC KEY-----`
)

func TestValidatePodSpec(t *testing.T) {
	tag := name.MustParseReference("gcr.io/distroless/static:nonroot")
	// Resolved via crane digest on 2021/09/25
	digest := name.MustParseReference("gcr.io/distroless/static:nonroot@sha256:be5d77c62dbe7fedfb0a4e5ec2f91078080800ab1f18358e5f31fcc8faa023c4")

	ctx, _ := rtesting.SetupFakeContext(t)
	si := fakesecret.Get(ctx)

	secretName := "blah"

	// Non-existent URL for testing complete failure
	badURL := apis.HTTP("http://example.com/")

	// Spin up a Fulcio that responds with a Root Cert
	fulcioServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Write([]byte(fulcioRootCert))
	}))
	t.Cleanup(fulcioServer.Close)
	fulcioURL, err := apis.ParseURL(fulcioServer.URL)
	if err != nil {
		t.Fatalf("Failed to parse fake Fulcio URL")
	}

	rekorServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Write([]byte(rekorResponse))
	}))
	t.Cleanup(rekorServer.Close)
	rekorURL, err := apis.ParseURL(rekorServer.URL)
	if err != nil {
		t.Fatalf("Failed to parse fake Rekor URL")
	}

	var authorityKeyCosignPub *ecdsa.PublicKey

	pems := parsePems([]byte(authorityKeyCosignPubString))
	if len(pems) > 0 {
		key, _ := x509.ParsePKIXPublicKey(pems[0].Bytes)
		authorityKeyCosignPub = key.(*ecdsa.PublicKey)
	} else {
		t.Errorf("Error parsing authority key from string")
	}

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

	kc := fakekube.Get(ctx)
	kc.CoreV1().ServiceAccounts("default").Create(ctx, &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
	}, metav1.CreateOptions{})

	v := NewValidator(ctx, secretName)

	cvs := cosignVerifySignatures
	defer func() {
		cosignVerifySignatures = cvs
	}()
	// Let's just say that everything is verified.
	pass := func(_ context.Context, _ name.Reference, _ *cosign.CheckOpts) (checkedSignatures []oci.Signature, bundleVerified bool, err error) {
		sig, err := static.NewSignature(nil, "")
		if err != nil {
			return nil, false, err
		}
		return []oci.Signature{sig}, true, nil
	}
	// Let's just say that everything is not verified.
	fail := func(_ context.Context, _ name.Reference, _ *cosign.CheckOpts) (checkedSignatures []oci.Signature, bundleVerified bool, err error) {
		return nil, false, errors.New("bad signature")
	}

	// Let's say it is verified if it is the expected Public Key
	authorityPublicKeyCVS := func(ctx context.Context, signedImgRef name.Reference, co *cosign.CheckOpts) (checkedSignatures []oci.Signature, bundleVerified bool, err error) {
		actualPublicKey, _ := co.SigVerifier.PublicKey()
		actualECDSAPubkey := actualPublicKey.(*ecdsa.PublicKey)
		actualKeyData := elliptic.Marshal(actualECDSAPubkey, actualECDSAPubkey.X, actualECDSAPubkey.Y)

		expectedKeyData := elliptic.Marshal(authorityKeyCosignPub, authorityKeyCosignPub.X, authorityKeyCosignPub.Y)

		if bytes.Equal(actualKeyData, expectedKeyData) {
			return pass(ctx, signedImgRef, co)
		}

		return fail(ctx, signedImgRef, co)
	}

	tests := []struct {
		name          string
		ps            *corev1.PodSpec
		want          *apis.FieldError
		cvs           func(context.Context, name.Reference, *cosign.CheckOpts) ([]oci.Signature, bool, error)
		customContext context.Context
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
			Message: `bad signature`,
			Paths:   []string{"containers[0].image"},
			Details: digest.String(),
		},
		cvs: fail,
	}, {
		name: "simple, no error, authority key",
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
		customContext: config.ToContext(context.Background(),
			&config.Config{
				ImagePolicyConfig: &config.ImagePolicyConfig{
					Policies: map[string]webhookcip.ClusterImagePolicy{
						"cluster-image-policy": {
							Images: []v1alpha1.ImagePattern{{
								Regex: ".*",
							}},
							Authorities: []webhookcip.Authority{
								{
									Key: &webhookcip.KeyRef{
										Data:       authorityKeyCosignPubString,
										PublicKeys: []crypto.PublicKey{authorityKeyCosignPub},
									},
								},
							},
						},
					},
				},
			},
		),
		cvs: authorityPublicKeyCVS,
	}, {
		name: "simple, error, authority keyless, bad fulcio",
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
		customContext: config.ToContext(context.Background(),
			&config.Config{
				ImagePolicyConfig: &config.ImagePolicyConfig{
					Policies: map[string]webhookcip.ClusterImagePolicy{
						"cluster-image-policy-keyless": {
							Images: []v1alpha1.ImagePattern{{
								Regex: ".*",
							}},
							Authorities: []webhookcip.Authority{
								{
									Keyless: &webhookcip.KeylessRef{
										URL: badURL,
									},
								},
							},
						},
					},
				},
			},
		),
		want: func() *apis.FieldError {
			var errs *apis.FieldError
			fe := apis.ErrGeneric("failed policy: cluster-image-policy-keyless", "image").ViaFieldIndex("initContainers", 0)
			fe.Details = fmt.Sprintf("%s %s", digest.String(), `fetching FulcioRoot: getting root cert: parse "http://http:%2F%2Fexample.com%2F/api/v1/rootCert": invalid port ":%2F%2Fexample.com%2F" after host`)
			errs = errs.Also(fe)
			fe2 := apis.ErrGeneric("failed policy: cluster-image-policy-keyless", "image").ViaFieldIndex("containers", 0)
			fe2.Details = fmt.Sprintf("%s %s", digest.String(), `fetching FulcioRoot: getting root cert: parse "http://http:%2F%2Fexample.com%2F/api/v1/rootCert": invalid port ":%2F%2Fexample.com%2F" after host`)
			errs = errs.Also(fe2)
			return errs
		}(),
		cvs: fail,
	}, {
		name: "simple, error, authority keyless, good fulcio, no rekor",
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
		customContext: config.ToContext(context.Background(),
			&config.Config{
				ImagePolicyConfig: &config.ImagePolicyConfig{
					Policies: map[string]webhookcip.ClusterImagePolicy{
						"cluster-image-policy-keyless": {
							Images: []v1alpha1.ImagePattern{{
								Regex: ".*",
							}},
							Authorities: []webhookcip.Authority{
								{
									Keyless: &webhookcip.KeylessRef{
										URL: fulcioURL,
									},
								},
							},
						},
					},
				},
			},
		),
		want: func() *apis.FieldError {
			var errs *apis.FieldError
			fe := apis.ErrGeneric("failed policy: cluster-image-policy-keyless", "image").ViaFieldIndex("initContainers", 0)
			fe.Details = fmt.Sprintf("%s validate signatures with fulcio: bad signature", digest.String())
			errs = errs.Also(fe)
			fe2 := apis.ErrGeneric("failed policy: cluster-image-policy-keyless", "image").ViaFieldIndex("containers", 0)
			fe2.Details = fmt.Sprintf("%s validate signatures with fulcio: bad signature", digest.String())
			errs = errs.Also(fe2)
			return errs
		}(),
		cvs: fail,
	}, {
		name: "simple, authority keyless checks out, good fulcio, bad cip policy",
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
		customContext: config.ToContext(context.Background(),
			&config.Config{
				ImagePolicyConfig: &config.ImagePolicyConfig{
					Policies: map[string]webhookcip.ClusterImagePolicy{
						"cluster-image-policy-keyless": {
							Images: []v1alpha1.ImagePattern{{
								Regex: ".*",
							}},
							Authorities: []webhookcip.Authority{
								{
									Keyless: &webhookcip.KeylessRef{
										URL: fulcioURL,
									},
								},
							},
							Policy: &webhookcip.AttestationPolicy{
								Name: "invalid json policy",
								Type: "cue",
								Data: `{"wontgo}`,
							},
						},
					},
				},
			},
		),
		want: func() *apis.FieldError {
			var errs *apis.FieldError
			fe := apis.ErrGeneric("failed policy: cluster-image-policy-keyless", "image").ViaFieldIndex("initContainers", 0)
			fe.Details = fmt.Sprintf("%s failed evaluating cue policy for ClusterImagePolicy : failed to compile the cue policy with error: string literal not terminated", digest.String())
			errs = errs.Also(fe)
			fe2 := apis.ErrGeneric("failed policy: cluster-image-policy-keyless", "image").ViaFieldIndex("containers", 0)
			fe2.Details = fmt.Sprintf("%s failed evaluating cue policy for ClusterImagePolicy : failed to compile the cue policy with error: string literal not terminated", digest.String())
			errs = errs.Also(fe2)
			return errs
		}(),
		cvs: pass,
	}, {
		name: "simple, no error, authority keyless, good fulcio",
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
		customContext: config.ToContext(context.Background(),
			&config.Config{
				ImagePolicyConfig: &config.ImagePolicyConfig{
					Policies: map[string]webhookcip.ClusterImagePolicy{
						"cluster-image-policy-keyless": {
							Images: []v1alpha1.ImagePattern{{
								Regex: ".*",
							}},
							Authorities: []webhookcip.Authority{
								{
									Keyless: &webhookcip.KeylessRef{
										URL: fulcioURL,
									},
								},
							},
						},
					},
				},
			},
		),
		cvs: pass,
	}, {
		name: "simple, error, authority keyless, good fulcio, bad rekor",
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
		customContext: config.ToContext(context.Background(),
			&config.Config{
				ImagePolicyConfig: &config.ImagePolicyConfig{
					Policies: map[string]webhookcip.ClusterImagePolicy{
						"cluster-image-policy-keyless": {
							Images: []v1alpha1.ImagePattern{{
								Regex: ".*",
							}},
							Authorities: []webhookcip.Authority{
								{
									Keyless: &webhookcip.KeylessRef{
										URL: fulcioURL,
									},
									CTLog: &v1alpha1.TLog{
										URL: rekorURL,
									},
								},
							},
						},
					},
				},
			},
		),
		want: func() *apis.FieldError {
			var errs *apis.FieldError
			fe := apis.ErrGeneric("failed policy: cluster-image-policy-keyless", "image").ViaFieldIndex("initContainers", 0)
			fe.Details = fmt.Sprintf("%s validate signatures with fulcio: bad signature", digest.String())
			errs = errs.Also(fe)
			fe2 := apis.ErrGeneric("failed policy: cluster-image-policy-keyless", "image").ViaFieldIndex("containers", 0)
			fe2.Details = fmt.Sprintf("%s validate signatures with fulcio: bad signature", digest.String())
			errs = errs.Also(fe2)
			return errs
		}(),
		cvs: fail,
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cosignVerifySignatures = test.cvs
			testContext := context.Background()

			if test.customContext != nil {
				testContext = test.customContext
			}

			// Check the core mechanics
			got := v.validatePodSpec(testContext, system.Namespace(), test.ps, k8schain.Options{})
			if (got != nil) != (test.want != nil) {
				t.Errorf("validatePodSpec() = %v, wanted %v", got, test.want)
			} else if got != nil && got.Error() != test.want.Error() {
				t.Errorf("validatePodSpec() = %v, wanted %v", got, test.want)
			}

			// Check wrapped in a Pod
			pod := &duckv1.Pod{
				Spec: *test.ps,
			}
			got = v.ValidatePod(testContext, pod)
			want := test.want.ViaField("spec")
			if (got != nil) != (want != nil) {
				t.Errorf("ValidatePod() = %v, wanted %v", got, want)
			} else if got != nil && got.Error() != want.Error() {
				t.Errorf("ValidatePod() = %v, wanted %v", got, want)
			}
			// Check that we don't block things being deleted.
			pod.DeletionTimestamp = &metav1.Time{Time: time.Now()}
			if got := v.ValidatePod(testContext, pod); got != nil {
				t.Errorf("ValidatePod() = %v, wanted nil", got)
			}

			// Check wrapped in a WithPod
			withPod := &duckv1.WithPod{
				Spec: duckv1.WithPodSpec{
					Template: duckv1.PodSpecable{
						Spec: *test.ps,
					},
				},
			}
			got = v.ValidatePodSpecable(testContext, withPod)
			want = test.want.ViaField("spec.template.spec")
			if (got != nil) != (want != nil) {
				t.Errorf("ValidatePodSpecable() = %v, wanted %v", got, want)
			} else if got != nil && got.Error() != want.Error() {
				t.Errorf("ValidatePodSpecable() = %v, wanted %v", got, want)
			}
			// Check that we don't block things being deleted.
			withPod.DeletionTimestamp = &metav1.Time{Time: time.Now()}
			if got := v.ValidatePodSpecable(testContext, withPod); got != nil {
				t.Errorf("ValidatePodSpecable() = %v, wanted nil", got)
			}
		})
	}
}

func TestValidateCronJob(t *testing.T) {
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
			// No data should make us verify against Fulcio.
		},
	})

	kc := fakekube.Get(ctx)
	kc.CoreV1().ServiceAccounts("default").Create(ctx, &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
	}, metav1.CreateOptions{})

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
	// Let's just say that everything is not verified.
	fail := func(ctx context.Context, signedImgRef name.Reference, co *cosign.CheckOpts) (checkedSignatures []oci.Signature, bundleVerified bool, err error) {
		return nil, false, errors.New("bad signature")
	}

	tests := []struct {
		name string
		c    *duckv1.CronJob
		want *apis.FieldError
		cvs  func(context.Context, name.Reference, *cosign.CheckOpts) ([]oci.Signature, bool, error)
	}{{
		name: "simple, no error",
		c: &duckv1.CronJob{
			Spec: batchv1.CronJobSpec{
				JobTemplate: batchv1.JobTemplateSpec{
					Spec: batchv1.JobSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								InitContainers: []corev1.Container{{
									Name:  "setup-stuff",
									Image: digest.String(),
								}},
								Containers: []corev1.Container{{
									Name:  "user-container",
									Image: digest.String(),
								}},
							},
						},
					},
				},
			},
		},
		cvs: pass,
	}, {
		name: "k8schain error (bad service account)",
		c: &duckv1.CronJob{
			Spec: batchv1.CronJobSpec{
				JobTemplate: batchv1.JobTemplateSpec{
					Spec: batchv1.JobSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								ServiceAccountName: "not-found",
								InitContainers: []corev1.Container{{
									Name:  "setup-stuff",
									Image: digest.String(),
								}},
								Containers: []corev1.Container{{
									Name:  "user-container",
									Image: digest.String(),
								}},
							},
						},
					},
				},
			},
		},
		want: &apis.FieldError{
			Message: `serviceaccounts "not-found" not found`,
			Paths:   []string{"spec.jobTemplate.spec.template.spec"},
		},
	}, {
		name: "k8schain error (bad pull secret)",
		c: &duckv1.CronJob{
			Spec: batchv1.CronJobSpec{
				JobTemplate: batchv1.JobTemplateSpec{
					Spec: batchv1.JobSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								ImagePullSecrets: []corev1.LocalObjectReference{{
									Name: "not-found",
								}},
								InitContainers: []corev1.Container{{
									Name:  "setup-stuff",
									Image: digest.String(),
								}},
								Containers: []corev1.Container{{
									Name:  "user-container",
									Image: digest.String(),
								}},
							},
						},
					},
				},
			},
		},
		want: &apis.FieldError{
			Message: `secrets "not-found" not found`,
			Paths:   []string{"spec.jobTemplate.spec.template.spec"},
		},
	}, {
		name: "bad reference",
		c: &duckv1.CronJob{
			Spec: batchv1.CronJobSpec{
				JobTemplate: batchv1.JobTemplateSpec{
					Spec: batchv1.JobSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{{
									Name:  "user-container",
									Image: "in@valid",
								}},
							},
						},
					},
				},
			},
		},
		want: &apis.FieldError{
			Message: `could not parse reference: in@valid`,
			Paths:   []string{"spec.jobTemplate.spec.template.spec.containers[0].image"},
		},
		cvs: fail,
	}, {
		name: "not digest",
		c: &duckv1.CronJob{
			Spec: batchv1.CronJobSpec{
				JobTemplate: batchv1.JobTemplateSpec{
					Spec: batchv1.JobSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{{
									Name:  "user-container",
									Image: tag.String(),
								}},
							},
						},
					},
				},
			},
		},
		want: &apis.FieldError{
			Message: `invalid value: gcr.io/distroless/static:nonroot must be an image digest`,
			Paths:   []string{"spec.jobTemplate.spec.template.spec.containers[0].image"},
		},
		cvs: fail,
	}, {
		name: "bad signature",
		c: &duckv1.CronJob{
			Spec: batchv1.CronJobSpec{
				JobTemplate: batchv1.JobTemplateSpec{
					Spec: batchv1.JobSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{{
									Name:  "user-container",
									Image: digest.String(),
								}},
							},
						},
					},
				},
			},
		},
		want: &apis.FieldError{
			Message: `bad signature`,
			Paths:   []string{"spec.jobTemplate.spec.template.spec.containers[0].image"},
			Details: digest.String(),
		},
		cvs: fail,
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cosignVerifySignatures = test.cvs

			// Check the core mechanics
			got := v.ValidateCronJob(context.Background(), test.c)
			if (got != nil) != (test.want != nil) {
				t.Errorf("validateCronJob() = %v, wanted %v", got, test.want)
			} else if got != nil && got.Error() != test.want.Error() {
				t.Errorf("validateCronJob() = %v, wanted %v", got, test.want)
			}
			// Check that we don't block things being deleted.
			cronJob := test.c.DeepCopy()
			cronJob.DeletionTimestamp = &metav1.Time{Time: time.Now()}
			if got := v.ValidateCronJob(context.Background(), cronJob); got != nil {
				t.Errorf("ValidateCronJob() = %v, wanted nil", got)
			}
		})
	}
}

func TestResolvePodSpec(t *testing.T) {
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

	kc := fakekube.Get(ctx)
	kc.CoreV1().ServiceAccounts("default").Create(ctx, &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
	}, metav1.CreateOptions{})

	v := NewValidator(ctx, secretName)

	rrd := remoteResolveDigest
	defer func() {
		remoteResolveDigest = rrd
	}()
	resolve := func(ref name.Reference, opts ...remote.Option) (name.Digest, error) {
		return digest.(name.Digest), nil
	}

	tests := []struct {
		name string
		ps   *corev1.PodSpec
		want *corev1.PodSpec
		wc   func(context.Context) context.Context
		rrd  func(name.Reference, ...remote.Option) (name.Digest, error)
	}{{
		name: "nothing changed (not the right update)",
		ps: &corev1.PodSpec{
			InitContainers: []corev1.Container{{
				Name:  "setup-stuff",
				Image: tag.String(),
			}},
			Containers: []corev1.Container{{
				Name:  "user-container",
				Image: tag.String(),
			}},
		},
		want: &corev1.PodSpec{
			InitContainers: []corev1.Container{{
				Name:  "setup-stuff",
				Image: tag.String(),
			}},
			Containers: []corev1.Container{{
				Name:  "user-container",
				Image: tag.String(),
			}},
		},
		rrd: resolve,
	}, {
		name: "nothing changed (bad reference)",
		ps: &corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "user-container",
				Image: "in@valid",
			}},
		},
		want: &corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "user-container",
				Image: "in@valid",
			}},
		},
		wc:  apis.WithinCreate,
		rrd: resolve,
	}, {
		name: "nothing changed (unable to resolve)",
		ps: &corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "user-container",
				Image: tag.String(),
			}},
		},
		want: &corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "user-container",
				Image: tag.String(),
			}},
		},
		wc: apis.WithinCreate,
		rrd: func(r name.Reference, o ...remote.Option) (name.Digest, error) {
			return name.Digest{}, errors.New("boom")
		},
	}, {
		name: "digests resolve (in create)",
		ps: &corev1.PodSpec{
			InitContainers: []corev1.Container{{
				Name:  "setup-stuff",
				Image: tag.String(),
			}},
			Containers: []corev1.Container{{
				Name:  "user-container",
				Image: tag.String(),
			}},
		},
		want: &corev1.PodSpec{
			InitContainers: []corev1.Container{{
				Name:  "setup-stuff",
				Image: digest.String(),
			}},
			Containers: []corev1.Container{{
				Name:  "user-container",
				Image: digest.String(),
			}},
		},
		wc:  apis.WithinCreate,
		rrd: resolve,
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			remoteResolveDigest = test.rrd
			ctx := context.Background()
			if test.wc != nil {
				ctx = test.wc(context.Background())
			}

			// Check the core mechanics.
			got := test.ps.DeepCopy()
			v.resolvePodSpec(ctx, got, k8schain.Options{})
			if !cmp.Equal(got, test.want) {
				t.Errorf("resolvePodSpec = %s", cmp.Diff(got, test.want))
			}

			var want runtime.Object

			// Check wrapped in a Pod
			pod := &duckv1.Pod{Spec: *test.ps.DeepCopy()}
			want = &duckv1.Pod{Spec: *test.want.DeepCopy()}
			v.ResolvePod(ctx, pod)
			if !cmp.Equal(pod, want) {
				t.Errorf("ResolvePod = %s", cmp.Diff(pod, want))
			}

			// Check that nothing happens when it's being deleted.
			pod = &duckv1.Pod{Spec: *test.ps.DeepCopy()}
			pod.DeletionTimestamp = &metav1.Time{Time: time.Now()}
			want = pod.DeepCopy()
			v.ResolvePod(ctx, pod)
			if !cmp.Equal(pod, want) {
				t.Errorf("ResolvePod = %s", cmp.Diff(pod, want))
			}

			// Check wrapped in a WithPod
			withPod := &duckv1.WithPod{
				Spec: duckv1.WithPodSpec{
					Template: duckv1.PodSpecable{
						Spec: *test.ps.DeepCopy(),
					},
				},
			}
			want = &duckv1.WithPod{
				Spec: duckv1.WithPodSpec{
					Template: duckv1.PodSpecable{
						Spec: *test.want.DeepCopy(),
					},
				},
			}
			v.ResolvePodSpecable(ctx, withPod)
			if !cmp.Equal(withPod, want) {
				t.Errorf("ResolvePodSpecable = %s", cmp.Diff(withPod, want))
			}

			// Check that nothing happens when it's being deleted.
			withPod = &duckv1.WithPod{
				Spec: duckv1.WithPodSpec{
					Template: duckv1.PodSpecable{
						Spec: *test.ps.DeepCopy(),
					},
				},
			}
			withPod.DeletionTimestamp = &metav1.Time{Time: time.Now()}
			want = withPod.DeepCopy()
			v.ResolvePodSpecable(ctx, withPod)
			if !cmp.Equal(withPod, want) {
				t.Errorf("ResolvePodSpecable = %s", cmp.Diff(withPod, want))
			}
		})
	}
}

func TestResolveCronJob(t *testing.T) {
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

	kc := fakekube.Get(ctx)
	kc.CoreV1().ServiceAccounts("default").Create(ctx, &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
	}, metav1.CreateOptions{})

	v := NewValidator(ctx, secretName)

	rrd := remoteResolveDigest
	defer func() {
		remoteResolveDigest = rrd
	}()
	resolve := func(ref name.Reference, opts ...remote.Option) (name.Digest, error) {
		return digest.(name.Digest), nil
	}

	tests := []struct {
		name string
		c    *duckv1.CronJob
		want *duckv1.CronJob
		wc   func(context.Context) context.Context
		rrd  func(name.Reference, ...remote.Option) (name.Digest, error)
	}{{
		name: "nothing changed (not the right update)",
		c: &duckv1.CronJob{
			Spec: batchv1.CronJobSpec{
				JobTemplate: batchv1.JobTemplateSpec{
					Spec: batchv1.JobSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								InitContainers: []corev1.Container{{
									Name:  "setup-stuff",
									Image: tag.String(),
								}},
								Containers: []corev1.Container{{
									Name:  "user-container",
									Image: tag.String(),
								}},
							},
						},
					},
				},
			},
		},
		want: &duckv1.CronJob{
			Spec: batchv1.CronJobSpec{
				JobTemplate: batchv1.JobTemplateSpec{
					Spec: batchv1.JobSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								InitContainers: []corev1.Container{{
									Name:  "setup-stuff",
									Image: tag.String(),
								}},
								Containers: []corev1.Container{{
									Name:  "user-container",
									Image: tag.String(),
								}},
							},
						},
					},
				},
			},
		},
		rrd: resolve,
	}, {
		name: "nothing changed (bad reference)",
		c: &duckv1.CronJob{
			Spec: batchv1.CronJobSpec{
				JobTemplate: batchv1.JobTemplateSpec{
					Spec: batchv1.JobSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{{
									Name:  "user-container",
									Image: "in@valid",
								}},
							},
						},
					},
				},
			},
		},
		want: &duckv1.CronJob{
			Spec: batchv1.CronJobSpec{
				JobTemplate: batchv1.JobTemplateSpec{
					Spec: batchv1.JobSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{{
									Name:  "user-container",
									Image: "in@valid",
								}},
							},
						},
					},
				},
			},
		},
		wc:  apis.WithinCreate,
		rrd: resolve,
	}, {
		name: "nothing changed (unable to resolve)",
		c: &duckv1.CronJob{
			Spec: batchv1.CronJobSpec{
				JobTemplate: batchv1.JobTemplateSpec{
					Spec: batchv1.JobSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{{
									Name:  "user-container",
									Image: "in@valid",
								}},
							},
						},
					},
				},
			},
		},
		want: &duckv1.CronJob{
			Spec: batchv1.CronJobSpec{
				JobTemplate: batchv1.JobTemplateSpec{
					Spec: batchv1.JobSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{{
									Name:  "user-container",
									Image: "in@valid",
								}},
							},
						},
					},
				},
			},
		},
		wc: apis.WithinCreate,
		rrd: func(r name.Reference, o ...remote.Option) (name.Digest, error) {
			return name.Digest{}, errors.New("boom")
		},
	}, {
		name: "digests resolve (in create)",
		c: &duckv1.CronJob{
			Spec: batchv1.CronJobSpec{
				JobTemplate: batchv1.JobTemplateSpec{
					Spec: batchv1.JobSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								InitContainers: []corev1.Container{{
									Name:  "setup-stuff",
									Image: tag.String(),
								}},
								Containers: []corev1.Container{{
									Name:  "user-container",
									Image: tag.String(),
								}},
							},
						},
					},
				},
			},
		},
		want: &duckv1.CronJob{
			Spec: batchv1.CronJobSpec{
				JobTemplate: batchv1.JobTemplateSpec{
					Spec: batchv1.JobSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								InitContainers: []corev1.Container{{
									Name:  "setup-stuff",
									Image: digest.String(),
								}},
								Containers: []corev1.Container{{
									Name:  "user-container",
									Image: digest.String(),
								}},
							},
						},
					},
				},
			},
		},
		wc:  apis.WithinCreate,
		rrd: resolve,
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			remoteResolveDigest = test.rrd
			ctx := context.Background()
			if test.wc != nil {
				ctx = test.wc(context.Background())
			}

			var want runtime.Object

			cronJob := test.c.DeepCopy()
			want = test.want.DeepCopy()
			v.ResolveCronJob(ctx, cronJob)
			if !cmp.Equal(cronJob, want) {
				t.Errorf("ResolveCronJob = %s", cmp.Diff(cronJob, want))
			}

			// Check that nothing happens when it's being deleted.
			cronJob = test.c.DeepCopy()
			cronJob.DeletionTimestamp = &metav1.Time{Time: time.Now()}
			want = cronJob.DeepCopy()
			v.ResolveCronJob(ctx, cronJob)
			if !cmp.Equal(cronJob, want) {
				t.Errorf("ResolveCronJob = %s", cmp.Diff(cronJob, want))
			}
		})
	}
}

func TestValidatePolicy(t *testing.T) {
	// Resolved via crane digest on 2021/09/25
	digest := name.MustParseReference("gcr.io/distroless/static:nonroot@sha256:be5d77c62dbe7fedfb0a4e5ec2f91078080800ab1f18358e5f31fcc8faa023c4")

	ctx, _ := rtesting.SetupFakeContext(t)
	si := fakesecret.Get(ctx)

	secretName := "blah"

	// Non-existent URL for testing complete failure
	badURL := apis.HTTP("http://example.com/")
	t.Logf("badURL: %s", badURL.String())

	// Spin up a Fulcio that responds with a Root Cert
	fulcioServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Write([]byte(fulcioRootCert))
	}))
	t.Cleanup(fulcioServer.Close)
	fulcioURL, err := apis.ParseURL(fulcioServer.URL)
	if err != nil {
		t.Fatalf("Failed to parse fake Fulcio URL")
	}
	t.Logf("fulcioURL: %s", fulcioURL.String())

	rekorServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Write([]byte(rekorResponse))
	}))
	t.Cleanup(rekorServer.Close)
	rekorURL, err := apis.ParseURL(rekorServer.URL)
	if err != nil {
		t.Fatalf("Failed to parse fake Rekor URL")
	}
	t.Logf("rekorURL: %s", rekorURL.String())
	var authorityKeyCosignPub *ecdsa.PublicKey

	pems := parsePems([]byte(authorityKeyCosignPubString))
	if len(pems) > 0 {
		key, _ := x509.ParsePKIXPublicKey(pems[0].Bytes)
		authorityKeyCosignPub = key.(*ecdsa.PublicKey)
	} else {
		t.Errorf("Error parsing authority key from string")
	}

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

	cvs := cosignVerifySignatures
	defer func() {
		cosignVerifySignatures = cvs
	}()
	// Let's just say that everything is verified.
	pass := func(_ context.Context, _ name.Reference, _ *cosign.CheckOpts) (checkedSignatures []oci.Signature, bundleVerified bool, err error) {
		sig, err := static.NewSignature(nil, "")
		if err != nil {
			return nil, false, err
		}
		return []oci.Signature{sig}, true, nil
	}
	// Let's just say that everything is not verified.
	fail := func(_ context.Context, _ name.Reference, _ *cosign.CheckOpts) (checkedSignatures []oci.Signature, bundleVerified bool, err error) {
		return nil, false, errors.New("bad signature")
	}

	// Let's say it is verified if it is the expected Public Key
	authorityPublicKeyCVS := func(ctx context.Context, signedImgRef name.Reference, co *cosign.CheckOpts) (checkedSignatures []oci.Signature, bundleVerified bool, err error) {
		actualPublicKey, _ := co.SigVerifier.PublicKey()
		actualECDSAPubkey := actualPublicKey.(*ecdsa.PublicKey)
		actualKeyData := elliptic.Marshal(actualECDSAPubkey, actualECDSAPubkey.X, actualECDSAPubkey.Y)

		expectedKeyData := elliptic.Marshal(authorityKeyCosignPub, authorityKeyCosignPub.X, authorityKeyCosignPub.Y)

		if bytes.Equal(actualKeyData, expectedKeyData) {
			return pass(ctx, signedImgRef, co)
		}

		return fail(ctx, signedImgRef, co)
	}

	tests := []struct {
		name          string
		policy        webhookcip.ClusterImagePolicy
		want          *PolicyResult
		wantErrs      []string
		cva           func(context.Context, name.Reference, *cosign.CheckOpts) ([]oci.Signature, bool, error)
		cvs           func(context.Context, name.Reference, *cosign.CheckOpts) ([]oci.Signature, bool, error)
		customContext context.Context
	}{{
		name: "simple, public key, no matches",
		policy: webhookcip.ClusterImagePolicy{
			Authorities: []webhookcip.Authority{{
				Name: "authority-0",
				Key: &webhookcip.KeyRef{
					PublicKeys: []crypto.PublicKey{authorityKeyCosignPub},
				},
			}},
		},
		wantErrs: []string{"failed to validate public keys with authority authority-0 for gcr.io/distroless/static@sha256:be5d77c62dbe7fedfb0a4e5ec2f91078080800ab1f18358e5f31fcc8faa023c4: bad signature"},
		cvs:      fail,
	}, {
		name: "simple, public key, works",
		policy: webhookcip.ClusterImagePolicy{
			Authorities: []webhookcip.Authority{{
				Name: "authority-0",
				Key: &webhookcip.KeyRef{
					PublicKeys: []crypto.PublicKey{authorityKeyCosignPub},
				},
			}},
		},
		want: &PolicyResult{
			AuthorityMatches: map[string]AuthorityMatch{
				"authority-0": {
					Signatures: []PolicySignature{{
						Subject: "PLACEHOLDER",
						Issuer:  "PLACEHOLDER"}},
				}},
		},
		cvs: pass,
	}, {
		name: "simple, public key, no error",
		policy: webhookcip.ClusterImagePolicy{
			Authorities: []webhookcip.Authority{{
				Name: "authority-0",
				Key: &webhookcip.KeyRef{
					PublicKeys: []crypto.PublicKey{authorityKeyCosignPub},
				},
			}},
		},
		want: &PolicyResult{
			AuthorityMatches: map[string]AuthorityMatch{
				"authority-0": {
					Signatures: []PolicySignature{{
						Subject: "PLACEHOLDER",
						Issuer:  "PLACEHOLDER"}},
				}},
		},
		cvs: authorityPublicKeyCVS,
	}, {
		name: "simple, keyless attestation, works",
		policy: webhookcip.ClusterImagePolicy{
			Authorities: []webhookcip.Authority{{
				Name: "authority-0",
				Keyless: &webhookcip.KeylessRef{
					URL: fulcioURL,
				},
				Attestations: []webhookcip.AttestationPolicy{{
					Name:          "test-att",
					PredicateType: "custom",
				}},
			},
			},
		},
		want: &PolicyResult{
			AuthorityMatches: map[string]AuthorityMatch{
				"authority-0": {
					Attestations: map[string][]PolicySignature{"test-att": {{
						Subject: "PLACEHOLDER",
						Issuer:  "PLACEHOLDER"}},
					}}},
		},
		cva: pass,
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cosignVerifySignatures = test.cvs
			cosignVerifyAttestations = test.cva
			testContext := context.Background()

			if test.customContext != nil {
				testContext = test.customContext
			}
			got, gotErrs := ValidatePolicy(testContext, system.Namespace(), digest, test.policy)
			validateErrors(t, test.wantErrs, gotErrs)
			if !reflect.DeepEqual(test.want, got) {
				t.Errorf("unexpected PolicyResult, want: %+v got: %+v", test.want, got)
			}
		})
	}
}

func validateErrors(t *testing.T, wantErr []string, got []error) {
	t.Helper()
	if len(wantErr) != len(got) {
		t.Errorf("Wanted %d errors got %d", len(wantErr), len(got))
	} else {
		for i, want := range wantErr {
			if !strings.Contains(got[i].Error(), want) {
				t.Errorf("Unwanted error at %d want: %s got: %s", i, want, got[i])
			}
		}
	}
}

func TestValidatePolicyCancelled(t *testing.T) {
	var authorityKeyCosignPub *ecdsa.PublicKey
	pems := parsePems([]byte(authorityKeyCosignPubString))
	if len(pems) > 0 {
		key, _ := x509.ParsePKIXPublicKey(pems[0].Bytes)
		authorityKeyCosignPub = key.(*ecdsa.PublicKey)
	} else {
		t.Errorf("Error parsing authority key from string")
	}
	// Resolved via crane digest on 2021/09/25
	digest := name.MustParseReference("gcr.io/distroless/static:nonroot@sha256:be5d77c62dbe7fedfb0a4e5ec2f91078080800ab1f18358e5f31fcc8faa023c4")

	testContext, cancelFunc := context.WithCancel(context.Background())
	cip := webhookcip.ClusterImagePolicy{
		Authorities: []webhookcip.Authority{{
			Name: "authority-0",
			Key: &webhookcip.KeyRef{
				PublicKeys: []crypto.PublicKey{authorityKeyCosignPub},
			},
		}},
	}
	wantErrs := []string{"context was canceled before validation completed"}
	cancelFunc()
	_, gotErrs := ValidatePolicy(testContext, system.Namespace(), digest, cip)
	validateErrors(t, wantErrs, gotErrs)
}

func TestValidatePoliciesCancelled(t *testing.T) {
	var authorityKeyCosignPub *ecdsa.PublicKey
	pems := parsePems([]byte(authorityKeyCosignPubString))
	if len(pems) > 0 {
		key, _ := x509.ParsePKIXPublicKey(pems[0].Bytes)
		authorityKeyCosignPub = key.(*ecdsa.PublicKey)
	} else {
		t.Errorf("Error parsing authority key from string")
	}
	// Resolved via crane digest on 2021/09/25
	digest := name.MustParseReference("gcr.io/distroless/static:nonroot@sha256:be5d77c62dbe7fedfb0a4e5ec2f91078080800ab1f18358e5f31fcc8faa023c4")

	testContext, cancelFunc := context.WithCancel(context.Background())
	cip := webhookcip.ClusterImagePolicy{
		Authorities: []webhookcip.Authority{{
			Name: "authority-0",
			Key: &webhookcip.KeyRef{
				PublicKeys: []crypto.PublicKey{authorityKeyCosignPub},
			},
		}},
	}
	wantErrs := []string{"context was canceled before validation completed"}
	cancelFunc()
	_, gotErrs := validatePolicies(testContext, system.Namespace(), digest, map[string]webhookcip.ClusterImagePolicy{"testcip": cip})
	validateErrors(t, wantErrs, gotErrs["internalerror"])
}
