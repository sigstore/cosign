# Image policy for cosigned

<!-- toc -->
- [Summary](#summary)
- [Motivation](#motivation)
  - [Goals](#goals)
  - [Future-Goals](#future-goals)
- [Proposal](#proposal)
  - [User Stories (Optional)](#user-stories-optional)
    - [Story 1](#story-1)
    - [Story 2](#story-2)
  - [Notes/Constraints/Caveats (Optional)](#notesconstraintscaveats-optional)
- [Design Details](#design-details)
<!-- /toc -->

## Summary

The current implementation of the `cosigned` admission controller requires that a secret be configured, containing PEM encoded public keys to be used to verify image signatures before deployment. While this may be effective for a small subset of keys, it can quickly become unwieldy when working with assets from multiple registries, or in a multi-tenant environment.

Here we propose introducing a cluster-scoped CRD, where keys may be specified per-registry and where cluster administrators may choose to fail open or to fail closed when matching keys may not be found.

## Motivation

As a critical component in maintaining a secure deployment environment, cosigned must be able to readily support fine-grained control over the validation of image signatures across multiple public and private registries.

### Goals
* Provide a positive user experience by simplifying the definition of image policies.
* Allow cluster administrators to easily verify image signatures from multiple registries against a potentially large number of signing keys.
* Reduce verification time by targeting keys to specific registries.
* Enable signature verification in a multi-tenant environment.
* Allow users to change policy behaviour at runtime.

### Future-Goals

* Verify that container images already running on a cluster still have valid signatures (i.e.: if a signature is revoked then any containers running on a cluster that were signed with that signature should be evicted or flagged as invalid).

## Proposal

The cosigned admission controller should look for ClusterImagePolicies which contain:
* Patterns
* Public keys to be used for images that match the pattern
* Excluded namespaces

```yaml
apiVersion: sigstore.dev/v1alpha1
kind: ClusterImagePolicy
metadata:
  name: image-policy
spec:
  verification:
    exclude:
      resources:
        namespaces:
        - cosign-system
        - kube-system
        - cert-manager
    keys:
    - name: cosign-key-1
      publicKey: <public-key>
    - name: cosign-key-prod
      publicKey: <public-key>     
    images:
    - namePattern: my.registry.org/library/*
      keys:
      - name: cosign-key-1
    - namePattern: prod.*.registry.org/team/*
      keys:
      - name: cosign-key-prod
```
Keys are defined as a list to avoid duplication across image repositories. Keys are then associated with image patterns by name.
The conditions for the cosigned admission controller to trigger does not change for this proposal. However, once the admission controller has fired:
1. The admission controller goes through the list of containers in the pod, and tries to match each container image against the patterns specified in the image policy in the specified order.  
    1. If the pattern matches, the mutating webhook tries to verify the signature of the image. 
        - If at least one public key successfully verifies the signature of the image, the pod is allowed to be created
        - If none of the public keys can successfully verify the signature, the pod is not allowed to be created 
    1. If no patterns match
        - The container bypasses the signature verification if the `AllowUnmatchedImages` flag is true. Warning will be sent back to the user in the command line
        - The container is blocked if the `AllowUnmatchedImages` flag is false


### User Stories (Optional)

This section lists the user stories:
- Platform operator, single-tenant
- Platform operator, multi-tenant

#### Story 1
##### Platform operator, single-tenant

As a platform operator for a small enterprise, I am responsible for all deployments to a single, managed k8s cluster. Images are pulled from a combination of private and public registries. I would like to define a single image policy for my entire cluster.

In the simplest use case, a single ClusterImagePolicy is defined that contains all anticipated public keys necessary to verify images as they are deployed. Verification simply requires that keys for matched registries may be identified.

Where no matching registry/key combinations are found, images are either rejected or allowed to pass according to the image policy.

#### Story 2
##### Platform operator, multi-tenant 

As a platform operator for a moderately sized enterprise with multiple, independent development teams, I require that all images are signed and verified, and that development teams are responsible for sourcing their own images. I would like to define a broad, cluster-wide image policy, while allowing developers to define local policies.

A broad, cluster-scoped policy provides some of the necessary registry/key definitions, while namespaced image policies may be provided to add additional registries and keys - perhaps provided on a team-by-team basis.

Whether unmatched images are rejected or allowed to pass is likely to be defined at the cluster-level, while additional registry/key combinations are defined in a namespaced ImagePolicy definition.

### Notes/Constraints/Caveats (Optional)
1. Should other resources like deployment, daemonset etc need to be specified in the policy to be ecluded from verification?
1. Should we have a `include` specification in the policy?
    1. Would namespace scoped policy help with namespaces opting in for verification?
    1. Can we assume that having a policy would mean that everything is included unless explicitly excluded

## Design Details

### Assumptions
- Multiple keys may be associated with each matching repository path/subpath
- As multiple keys may be associated with a repository, it is possible that there would be no conflicts when reconciling multiple image policies
- Currently the CRD specified excluded directories, in contrast to cosigned include labels. Both may coexist. This is a point for discussion.

