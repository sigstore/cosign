## cosign verify-attestation

Verify an attestation on the supplied container image

### Synopsis

Verify an attestation on an image by checking the claims
against the transparency log.

```
cosign verify-attestation [flags]
```

### Examples

```
  cosign verify-attestation --key <key path>|<key url>|<kms uri> <image uri> [<image uri> ...]

  # verify cosign attestations on the image
  cosign verify-attestation <IMAGE>

  # verify multiple images
  cosign verify-attestation <IMAGE_1> <IMAGE_2> ...

  # additionally verify specified annotations
  cosign verify-attestation -a key1=val1 -a key2=val2 <IMAGE>

  # (experimental) additionally, verify with the transparency log
  COSIGN_EXPERIMENTAL=1 cosign verify-attestation <IMAGE>

  # verify image with public key
  cosign verify-attestation --key cosign.pub <IMAGE>

  # verify image attestations with an on-disk signed image from 'cosign save'
  cosign verify-attestation --key cosign.pub --local-image <PATH>

  # verify image with public key provided by URL
  cosign verify-attestation --key https://host.for/<FILE> <IMAGE>

  # verify image with public key stored in Google Cloud KMS
  cosign verify-attestation --key gcpkms://projects/<PROJECT>/locations/global/keyRings/<KEYRING>/cryptoKeys/<KEY> <IMAGE>

  # verify image with public key stored in Hashicorp Vault
  cosign verify-attestation --key hashivault:///<KEY> <IMAGE>

  # verify image with public key stored in GitLab with project name
  cosign verify-attestation --key gitlab://[OWNER]/[PROJECT_NAME] <IMAGE>

  # verify image with public key stored in GitLab with project id
  cosign verify-attestation --key gitlab://[PROJECT_ID] <IMAGE>

  # verify image with public key and validate attestation based on Rego policy
  cosign verify-attestation --key cosign.pub --type <PREDICATE_TYPE> --policy <REGO_POLICY> <IMAGE>

  # verify image with public key and validate attestation based on CUE policy
  cosign verify-attestation --key cosign.pub --type <PREDICATE_TYPE> --policy <CUE_POLICY> <IMAGE>
```

### Options

```
      --allow-insecure-registry                                                                  whether to allow insecure connections to registries. Don't use this for anything but testing
  -a, --annotations strings                                                                      extra key=value pairs to sign
      --attachment-tag-prefix [AttachmentTagPrefix]sha256-[TargetImageDigest].[AttachmentName]   optional custom prefix to use for attached image tags. Attachment images are tagged as: [AttachmentTagPrefix]sha256-[TargetImageDigest].[AttachmentName]
      --certificate string                                                                       path to the public certificate
      --certificate-chain string                                                                 path to a list of CA certificates in PEM format which will be needed when building the certificate chain for the signing certificate. Must start with the parent intermediate CA certificate of the signing certificate and end with the root certificate
      --certificate-email string                                                                 the email expected in a valid Fulcio certificate
      --certificate-oidc-issuer string                                                           the OIDC issuer expected in a valid Fulcio certificate, e.g. https://token.actions.githubusercontent.com or https://oauth2.sigstore.dev/auth
      --check-claims                                                                             whether to check the claims found (default true)
      --enforce-sct                                                                              whether to enforce that a certificate contain an embedded SCT, a proof of inclusion in a certificate transparency log
  -h, --help                                                                                     help for verify-attestation
      --k8s-keychain                                                                             whether to use the kubernetes keychain instead of the default keychain (supports workload identity).
      --key string                                                                               path to the public key file, KMS URI or Kubernetes Secret
      --local-image                                                                              whether the specified image is a path to an image saved locally via 'cosign save'
  -o, --output string                                                                            output format for the signing image information (json|text) (default "json")
      --policy strings                                                                           specify CUE or Rego files will be using for validation
      --rekor-url string                                                                         [EXPERIMENTAL] address of rekor STL server (default "https://rekor.sigstore.dev")
      --sk                                                                                       whether to use a hardware security key
      --slot string                                                                              security key slot to use for generated key (default: signature) (authentication|signature|card-authentication|key-management)
      --type string                                                                              specify a predicate type (slsaprovenance|link|spdx|spdxjson|cyclonedx|vuln|custom) or an URI (default "custom")
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -t, --timeout duration     timeout for commands (default 3m0s)
  -d, --verbose              log debug output
  -y, --yes                  skip confirmation prompts for non-destructive operations
```

### SEE ALSO

* [cosign](cosign.md)	 - A tool for Container Signing, Verification and Storage in an OCI registry.

