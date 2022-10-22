# Feature Stability

This doc covers feature stability in `cosign` as described in the [API Stability Policy](https://docs.sigstore.dev/api-stability) for Sigstore.

## Experimental
* Keyless signing using the `Fulcio` CA
* Storing signatures in a transparency log
* The `pkg/cosign/oci` client library

Some formats that cosign relies upon are not stable yet either:
* The SBOM specification for storing SBOMs in a container registry
* The In-Toto attestation format


## Beta
* All cosign subcommands, including flags and output


## General Availability

### Key Management

* fixed, text-based keys generated using `cosign generate-key-pair`
* cloud KMS-based keys generated using `cosign generate-key-pair -kms`
* keys generated on hardware tokens using the PIV interface using `cosign piv-tool`
* Kubernetes-secret based keys generated using `cosign generate-key-pair k8s://namespace/secretName`


### Artifact Types

* OCI and Docker Images
* Other artifacts that can be stored in a container registry, including:
  * Tekton Bundles
  * Helm Charts
  * WASM modules
* Text files and other binary blobs, using `cosign sign-blob`
