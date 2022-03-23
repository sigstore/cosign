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
	"crypto/x509"
	"fmt"
	"io"
	"net/http"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/authn/k8schain"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/pkg/apis/config"
	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
	rekor "github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/client"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	listersv1 "k8s.io/client-go/listers/core/v1"
	"knative.dev/pkg/apis"
	duckv1 "knative.dev/pkg/apis/duck/v1"
	kubeclient "knative.dev/pkg/client/injection/kube/client"
	secretinformer "knative.dev/pkg/injection/clients/namespacedkube/informers/core/v1/secret"
	"knative.dev/pkg/logging"
	"knative.dev/pkg/system"
)

type Validator struct {
	client     kubernetes.Interface
	lister     listersv1.SecretLister
	secretName string
}

func NewValidator(ctx context.Context, secretName string) *Validator {
	return &Validator{
		client:     kubeclient.Get(ctx),
		lister:     secretinformer.Get(ctx).Lister(),
		secretName: secretName,
	}
}

// ValidatePodSpecable implements duckv1.PodSpecValidator
func (v *Validator) ValidatePodSpecable(ctx context.Context, wp *duckv1.WithPod) *apis.FieldError {
	if wp.DeletionTimestamp != nil {
		// Don't block things that are being deleted.
		return nil
	}

	imagePullSecrets := make([]string, 0, len(wp.Spec.Template.Spec.ImagePullSecrets))
	for _, s := range wp.Spec.Template.Spec.ImagePullSecrets {
		imagePullSecrets = append(imagePullSecrets, s.Name)
	}
	opt := k8schain.Options{
		Namespace:          wp.Namespace,
		ServiceAccountName: wp.Spec.Template.Spec.ServiceAccountName,
		ImagePullSecrets:   imagePullSecrets,
	}
	return v.validatePodSpec(ctx, &wp.Spec.Template.Spec, opt).ViaField("spec.template.spec")
}

// ValidatePod implements duckv1.PodValidator
func (v *Validator) ValidatePod(ctx context.Context, p *duckv1.Pod) *apis.FieldError {
	if p.DeletionTimestamp != nil {
		// Don't block things that are being deleted.
		return nil
	}
	imagePullSecrets := make([]string, 0, len(p.Spec.ImagePullSecrets))
	for _, s := range p.Spec.ImagePullSecrets {
		imagePullSecrets = append(imagePullSecrets, s.Name)
	}
	opt := k8schain.Options{
		Namespace:          p.Namespace,
		ServiceAccountName: p.Spec.ServiceAccountName,
		ImagePullSecrets:   imagePullSecrets,
	}
	return v.validatePodSpec(ctx, &p.Spec, opt).ViaField("spec")
}

// ValidateCronJob implements duckv1.CronJobValidator
func (v *Validator) ValidateCronJob(ctx context.Context, c *duckv1.CronJob) *apis.FieldError {
	if c.DeletionTimestamp != nil {
		// Don't block things that are being deleted.
		return nil
	}
	imagePullSecrets := make([]string, 0, len(c.Spec.JobTemplate.Spec.Template.Spec.ImagePullSecrets))
	for _, s := range c.Spec.JobTemplate.Spec.Template.Spec.ImagePullSecrets {
		imagePullSecrets = append(imagePullSecrets, s.Name)
	}
	opt := k8schain.Options{
		Namespace:          c.Namespace,
		ServiceAccountName: c.Spec.JobTemplate.Spec.Template.Spec.ServiceAccountName,
		ImagePullSecrets:   imagePullSecrets,
	}
	return v.validatePodSpec(ctx, &c.Spec.JobTemplate.Spec.Template.Spec, opt).ViaField("spec.jobTemplate.spec.template.spec")
}

func (v *Validator) validatePodSpec(ctx context.Context, ps *corev1.PodSpec, opt k8schain.Options) (errs *apis.FieldError) {
	kc, err := k8schain.New(ctx, v.client, opt)
	if err != nil {
		logging.FromContext(ctx).Warnf("Unable to build k8schain: %v", err)
		return apis.ErrGeneric(err.Error(), apis.CurrentField)
	}

	s, err := v.lister.Secrets(system.Namespace()).Get(v.secretName)
	if err != nil {
		return apis.ErrGeneric(err.Error(), apis.CurrentField)
	}

	keys, kerr := getKeys(ctx, s.Data)
	if kerr != nil {
		return kerr
	}

	checkContainers := func(cs []corev1.Container, field string) {
		for i, c := range cs {
			ref, err := name.ParseReference(c.Image)
			if err != nil {
				errs = errs.Also(apis.ErrGeneric(err.Error(), "image").ViaFieldIndex(field, i))
				continue
			}

			// Require digests, otherwise the validation is meaningless
			// since the tag can move.
			if _, ok := ref.(name.Digest); !ok {
				errs = errs.Also(apis.ErrInvalidValue(
					fmt.Sprintf("%s must be an image digest", c.Image),
					"image",
				).ViaFieldIndex(field, i))
				continue
			}

			containerKeys := keys
			config := config.FromContext(ctx)
			if config != nil {
				fieldErrors := validateAuthorities(ctx, ref, kc, config)
				if fieldErrors != nil && len(fieldErrors) > 0 {
					// TODO:(dennyhoang) Enforce currently non-breaking errors https://github.com/sigstore/cosign/issues/1642
					logging.FromContext(ctx).Warnf("Failed to validate authorities for %s : %v", ref.Name(), fieldErrors)
				} else {
					logging.FromContext(ctx).Warnf("Validated authorities for %s", ref.Name())
				}
				continue
			}

			if err := valid(ctx, ref, containerKeys, ociremote.WithRemoteOptions(remote.WithAuthFromKeychain(kc))); err != nil {
				errorField := apis.ErrGeneric(err.Error(), "image").ViaFieldIndex(field, i)
				errorField.Details = c.Image
				errs = errs.Also(errorField)
				continue
			}
		}
	}

	checkContainers(ps.InitContainers, "initContainers")
	checkContainers(ps.Containers, "containers")

	return errs
}

//
func validateAuthorities(ctx context.Context, ref name.Reference, defaultKC authn.Keychain, config *config.Config, opts ...ociremote.Option) []error {
	ret := []error{}
	authorities, err := config.ImagePolicyConfig.GetAuthorities(ref.Name())
	if err != nil {
		return append(ret, errors.Wrap(err, "failed to GetAuthorities"))
	}

	for _, authority := range authorities {
		logging.FromContext(ctx).Infof("Checking Authority: %+v", authority)
		// TODO(vaikas): We currently only use the defaultKC, we have to look
		// at authority.Sources to determine additional information for the
		// WithRemoteOptions below, at least the 'TargetRepository'
		opts := ociremote.WithRemoteOptions(remote.WithAuthFromKeychain(defaultKC))

		if authority.Key != nil {
			// Get the key from authority data
			if authorityKeys, fieldErr := parseAuthorityKeys(ctx, authority.Key.Data); fieldErr != nil {
				ret = append(ret, errors.Wrap(fieldErr, "failed to parse Key values"))
			} else {
				// TODO(vaikas): I don't think this is right because the API doc
				// says it has to match all the policies, and I think we may
				// have to ensure _all_ the keys match, but valid (well, and
				// things it calls) succeed if any key matches.
				if err := valid(ctx, ref, authorityKeys, opts); err != nil {
					ret = append(ret, errors.Wrap(err, "failed to validate keys"))
					continue
				}
			}
		}
		if authority.Keyless != nil && authority.Keyless.URL != nil {
			logging.FromContext(ctx).Infof("Fetching FulcioRoot for %s : From: %s ", ref.Name(), authority.Keyless.URL)
			fulcioroot, err := getFulcioCert(authority.Keyless.URL)
			if err != nil {
				ret = append(ret, errors.Wrap(err, "failed to fetch FulcioRoot"))
				continue
			}
			var rekorClient *client.Rekor
			if authority.CTLog != nil && authority.CTLog.URL != nil {
				rekorClient, err = rekor.GetRekorClient(authority.CTLog.URL.String())
				if err != nil {
					logging.FromContext(ctx).Errorf("vaikas failed creating rekor client: +v", err)
					ret = append(ret, errors.Wrap(err, "failed creating Rekor client"))
					continue
				}
			}
			sps, err := validSignaturesWithFulcio(ctx, ref, fulcioroot, rekorClient, opts)
			if err != nil {
				logging.FromContext(ctx).Errorf("vaikas FAILED validSignatures: %v", err)
				ret = append(ret, errors.Wrap(err, "failed to validate signatures"))
			} else {
				if len(sps) > 0 {
					logging.FromContext(ctx).Infof("vaikas zomg validated signature, got %d signatures", len(sps))
				} else {
					logging.FromContext(ctx).Errorf("vaikas No validSignatures found ")
				}
			}
		}
	}
	return ret
}

// ResolvePodSpecable implements duckv1.PodSpecValidator
func (v *Validator) ResolvePodSpecable(ctx context.Context, wp *duckv1.WithPod) {
	if wp.DeletionTimestamp != nil {
		// Don't mess with things that are being deleted.
		return
	}

	imagePullSecrets := make([]string, 0, len(wp.Spec.Template.Spec.ImagePullSecrets))
	for _, s := range wp.Spec.Template.Spec.ImagePullSecrets {
		imagePullSecrets = append(imagePullSecrets, s.Name)
	}
	opt := k8schain.Options{
		Namespace:          wp.Namespace,
		ServiceAccountName: wp.Spec.Template.Spec.ServiceAccountName,
		ImagePullSecrets:   imagePullSecrets,
	}
	v.resolvePodSpec(ctx, &wp.Spec.Template.Spec, opt)
}

// ResolvePod implements duckv1.PodValidator
func (v *Validator) ResolvePod(ctx context.Context, p *duckv1.Pod) {
	if p.DeletionTimestamp != nil {
		// Don't mess with things that are being deleted.
		return
	}
	imagePullSecrets := make([]string, 0, len(p.Spec.ImagePullSecrets))
	for _, s := range p.Spec.ImagePullSecrets {
		imagePullSecrets = append(imagePullSecrets, s.Name)
	}
	opt := k8schain.Options{
		Namespace:          p.Namespace,
		ServiceAccountName: p.Spec.ServiceAccountName,
		ImagePullSecrets:   imagePullSecrets,
	}
	v.resolvePodSpec(ctx, &p.Spec, opt)
}

// ResolveCronJob implements duckv1.CronJobValidator
func (v *Validator) ResolveCronJob(ctx context.Context, c *duckv1.CronJob) {
	if c.DeletionTimestamp != nil {
		// Don't mess with things that are being deleted.
		return
	}
	imagePullSecrets := make([]string, 0, len(c.Spec.JobTemplate.Spec.Template.Spec.ImagePullSecrets))
	for _, s := range c.Spec.JobTemplate.Spec.Template.Spec.ImagePullSecrets {
		imagePullSecrets = append(imagePullSecrets, s.Name)
	}
	opt := k8schain.Options{
		Namespace:          c.Namespace,
		ServiceAccountName: c.Spec.JobTemplate.Spec.Template.Spec.ServiceAccountName,
		ImagePullSecrets:   imagePullSecrets,
	}
	v.resolvePodSpec(ctx, &c.Spec.JobTemplate.Spec.Template.Spec, opt)
}

// For testing
var remoteResolveDigest = ociremote.ResolveDigest

func (v *Validator) resolvePodSpec(ctx context.Context, ps *corev1.PodSpec, opt k8schain.Options) {
	kc, err := k8schain.New(ctx, v.client, opt)
	if err != nil {
		logging.FromContext(ctx).Warnf("Unable to build k8schain: %v", err)
		return
	}

	resolveContainers := func(cs []corev1.Container) {
		for i, c := range cs {
			ref, err := name.ParseReference(c.Image)
			if err != nil {
				logging.FromContext(ctx).Debugf("Unable to parse reference: %v", err)
				continue
			}

			// If we are in the context of a mutating webhook, then resolve the tag to a digest.
			switch {
			case apis.IsInCreate(ctx), apis.IsInUpdate(ctx):
				digest, err := remoteResolveDigest(ref, ociremote.WithRemoteOptions(remote.WithAuthFromKeychain(kc)))
				if err != nil {
					logging.FromContext(ctx).Debugf("Unable to resolve digest %q: %v", ref.String(), err)
					continue
				}
				cs[i].Image = digest.String()
			}
		}
	}

	resolveContainers(ps.InitContainers)
	resolveContainers(ps.Containers)
}

func getFulcioCert(u *apis.URL) (*x509.CertPool, error) {
	resp, err := http.Get(u.String())
	if err != nil {
		return nil, errors.Wrap(err, "doing http get")
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "reading http body")
	}
	cp := x509.NewCertPool()
	if !cp.AppendCertsFromPEM(body) {
		return nil, errors.New("error appending to root cert pool")
	}
	return cp, nil
}
