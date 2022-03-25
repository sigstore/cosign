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

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/authn/k8schain"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/pkg/apis/config"
	"github.com/sigstore/cosign/pkg/apis/cosigned/v1alpha1"
	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
	"github.com/sigstore/fulcio/pkg/api"
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

			// During the migration from the secret only validation into policy
			// based ones. If there were matching policies that successfully
			// validated the image, keep tally of it and if all Policies that
			// matched validated, skip the traditional one since they are not
			// necessarily going to play nicely together.
			passedPolicyChecks := false
			if config != nil {
				policies, err := config.ImagePolicyConfig.GetMatchingPolicies(ref.Name())
				if err != nil {
					errorField := apis.ErrGeneric(err.Error(), "image").ViaFieldIndex(field, i)
					errorField.Details = c.Image
					errs = errs.Also(errorField)
					continue
				}

				// If there is at least one policy that matches, that means it
				// has to be satisfied.
				if len(policies) > 0 {
					av, fieldErrors := validatePolicies(ctx, ref, kc, policies)
					if av != len(policies) {
						logging.FromContext(ctx).Warnf("Failed to validate at least one policy for %s", ref.Name())
						// Do we really want to add all the error details here?
						// Seems like we can just say which policy failed, so
						// doing that for now.
						for failingPolicy := range fieldErrors {
							errorField := apis.ErrGeneric(fmt.Sprintf("failed policy: %s", failingPolicy), "image").ViaFieldIndex(field, i)
							errorField.Details = c.Image
							errs = errs.Also(errorField)
						}
						// Because there was at least one policy that was
						// supposed to be validated, but it failed, then fail
						// this image. It should not fall through to the
						// traditional secret checking so it does not slip
						// through the policy cracks, and also to reduce noise
						// in the errors returned to the user.
						continue
					} else {
						logging.FromContext(ctx).Warnf("Validated authorities for %s", ref.Name())
						// Only say we passed (aka, we skip the traditidional check
						// below) if more than one authority was validated, which
						// means that there was a matching ClusterImagePolicy.
						if av > 0 {
							passedPolicyChecks = true
						}
					}
				}
			}

			if passedPolicyChecks {
				logging.FromContext(ctx).Debugf("Found at least one matching policy and it was validated for %s", ref.Name())
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

// validatePolicies will go through all the matching Policies and their
// Authorities for a given image. Returns the number of Policies that
// had at least one successful validation against it.
// If there's a policy that did not match, it will be returned in the map
// along with all the errors that caused it to fail.
// Note that if an image does not match any policies, it's perfectly
// reasonable that the return value is 0, nil since there were no errors, but
// the image was not validated against any matching policy and hence authority.
func validatePolicies(ctx context.Context, ref name.Reference, defaultKC authn.Keychain, policies map[string][]v1alpha1.Authority, _ ...ociremote.Option) (int, map[string][]error) {
	// For a policy that does not pass at least one authority, gather errors
	// here so that we can give meaningful errors to the user.
	ret := map[string][]error{}
	// For each matching policy it must validate at least one Authority within
	// it.
	// From the Design document, the part about multiple Policies matching:
	// "If multiple policies match a particular image, then ALL of those
	// policies must be satisfied for the image to be admitted."
	// So we keep a tally to make sure that all the policies matched.
	policiesValidated := 0
	// If none of the Authorities for a given policy pass the checks, gather
	// the errors here. If one passes, do not return the errors.
	authorityErrors := []error{}
	for p, authorities := range policies {
		logging.FromContext(ctx).Debugf("Checking Policy: %s", p)
		// Now the part about having multiple Authority sections within a
		// policy, any single match will do:
		// "When multiple authorities are specified, any of them may be used
		// to source the valid signature we are looking for to admit an image.""
		authoritiesValidated := 0
		for _, authority := range authorities {
			logging.FromContext(ctx).Debugf("Checking Authority: %+v", authority)
			// TODO(vaikas): We currently only use the defaultKC, we have to look
			// at authority.Sources to determine additional information for the
			// WithRemoteOptions below, at least the 'TargetRepository'
			// https://github.com/sigstore/cosign/issues/1651
			opts := ociremote.WithRemoteOptions(remote.WithAuthFromKeychain(defaultKC))

			if authority.Key != nil {
				// Get the key from authority data
				if authorityKeys, fieldErr := parseAuthorityKeys(ctx, authority.Key.Data); fieldErr != nil {
					authorityErrors = append(authorityErrors, errors.Wrap(fieldErr, "failed to parse Key values"))
				} else {
					// TODO(vaikas): What should happen if there are multiple keys
					// Is it even allowed? 'valid' returns success if any key
					// matches.
					// https://github.com/sigstore/cosign/issues/1652
					if err := valid(ctx, ref, authorityKeys, opts); err != nil {
						authorityErrors = append(authorityErrors, errors.Wrap(err, "failed to validate keys"))
						continue
					}
					// This authority matched, so mark it as validated and
					// continue through other policies, no need to look at more
					// of the Authorities.
					authoritiesValidated++
					break
				}
			}
			if authority.Keyless != nil && authority.Keyless.URL != nil {
				logging.FromContext(ctx).Debugf("Fetching FulcioRoot for %s : From: %s ", ref.Name(), authority.Keyless.URL)
				fulcioroot, err := getFulcioCert(authority.Keyless.URL)
				if err != nil {
					authorityErrors = append(authorityErrors, errors.Wrap(err, "fetching FulcioRoot"))
					continue
				}
				var rekorClient *client.Rekor
				if authority.CTLog != nil && authority.CTLog.URL != nil {
					logging.FromContext(ctx).Debugf("Using CTLog %s for %s", authority.CTLog.URL, ref.Name())
					rekorClient, err = rekor.GetRekorClient(authority.CTLog.URL.String())
					if err != nil {
						logging.FromContext(ctx).Errorf("failed creating rekor client: +v", err)
						authorityErrors = append(authorityErrors, errors.Wrap(err, "creating Rekor client"))
						continue
					}
				}
				sps, err := validSignaturesWithFulcio(ctx, ref, fulcioroot, rekorClient, opts)
				if err != nil {
					logging.FromContext(ctx).Errorf("failed validSignatures with fulcio for %s: %v", ref.Name(), err)
					authorityErrors = append(authorityErrors, errors.Wrap(err, "validate signatures with fulcio"))
				} else {
					if len(sps) > 0 {
						logging.FromContext(ctx).Debugf("validated signature for %s, got %d signatures", len(sps))
						// This authority matched, so mark it as validated and
						// continue through other policies, no need to look at
						// more of the Authorities.
						authoritiesValidated++
						break
					} else {
						logging.FromContext(ctx).Errorf("no validSignatures found for %s", ref.Name())
						authorityErrors = append(authorityErrors, fmt.Errorf("no valid signatures found for %s", ref.Name()))
					}
				}
			}
		}
		if authoritiesValidated > 0 {
			policiesValidated++
		} else {
			ret[p] = append(ret[p], authorityErrors...)
		}
	}
	return policiesValidated, ret
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
	fClient := api.NewClient(u.URL())
	rootCertResponse, err := fClient.RootCert()
	if err != nil {
		return nil, errors.Wrap(err, "getting root cert")
	}

	cp := x509.NewCertPool()
	if !cp.AppendCertsFromPEM(rootCertResponse.ChainPEM) {
		return nil, errors.New("error appending to root cert pool")
	}
	return cp, nil
}
