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

  # verify cosign attestations on the image against the transparency log
  cosign verify-attestation <IMAGE>

  # verify multiple images
  cosign verify-attestation <IMAGE_1> <IMAGE_2> ...

  # additionally verify specified annotations
  cosign verify-attestation -a key1=val1 -a key2=val2 <IMAGE>

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
      --allow-http-registry                                                                      whether to allow using HTTP protocol while connecting to registries. Don't use this for anything but testing
      --allow-insecure-registry                                                                  whether to allow insecure connections to registries (e.g., with expired or self-signed TLS certificates). Don't use this for anything but testing
      --attachment-tag-prefix [AttachmentTagPrefix]sha256-[TargetImageDigest].[AttachmentName]   optional custom prefix to use for attached image tags. Attachment images are tagged as: [AttachmentTagPrefix]sha256-[TargetImageDigest].[AttachmentName]
      --certificate string                                                                       path to the public certificate. The certificate will be verified against the Fulcio roots if the --certificate-chain option is not passed.
      --certificate-chain string                                                                 path to a list of CA certificates in PEM format which will be needed when building the certificate chain for the signing certificate. Must start with the parent intermediate CA certificate of the signing certificate and end with the root certificate
      --certificate-github-workflow-name string                                                  contains the workflow claim from the GitHub OIDC Identity token that contains the name of the executed workflow.
      --certificate-github-workflow-ref string                                                   contains the ref claim from the GitHub OIDC Identity token that contains the git ref that the workflow run was based upon.
      --certificate-github-workflow-repository string                                            contains the repository claim from the GitHub OIDC Identity token that contains the repository that the workflow run was based upon
      --certificate-github-workflow-sha string                                                   contains the sha claim from the GitHub OIDC Identity token that contains the commit SHA that the workflow run was based upon.
      --certificate-github-workflow-trigger string                                               contains the event_name claim from the GitHub OIDC Identity token that contains the name of the event that triggered the workflow run
      --certificate-identity string                                                              Required. The identity expected in a valid Fulcio certificate. Valid values include email address, DNS names, IP addresses, and URIs.
      --certificate-oidc-issuer string                                                           Required. The OIDC issuer expected in a valid Fulcio certificate, e.g. https://token.actions.githubusercontent.com or https://oauth2.sigstore.dev/auth
      --check-claims                                                                             whether to check the claims found (default true)
  -h, --help                                                                                     help for verify-attestation
      --insecure-ignore-sct                                                                      when set, verification will not check that a certificate contains an embedded SCT, a proof of inclusion in a certificate transparency log
      --insecure-skip-tlog-verify                                                                skip tlog verification
      --k8s-keychain                                                                             whether to use the kubernetes keychain instead of the default keychain (supports workload identity).
      --key string                                                                               path to the public key file, KMS URI or Kubernetes Secret
      --local-image                                                                              whether the specified image is a path to an image saved locally via 'cosign save'
      --offline                                                                                  only allow offline verification
  -o, --output string                                                                            output format for the signing image information (json|text) (default "json")
      --policy strings                                                                           specify CUE or Rego files will be using for validation
      --rekor-url string                                                                         [EXPERIMENTAL] address of rekor STL server (default "https://rekor.sigstore.dev")
      --sct string                                                                               path to a detached Signed Certificate Timestamp, formatted as a RFC6962 AddChainResponse struct. If a certificate contains an SCT, verification will check both the detached and embedded SCTs.
      --sk                                                                                       whether to use a hardware security key
      --slot string                                                                              security key slot to use for generated key (default: signature) (authentication|signature|card-authentication|key-management)
      --timestamp-cert-chain string                                                              path to certificate chain PEM file for the Timestamp Authority
      --type string                                                                              specify a predicate type (slsaprovenance|link|spdx|spdxjson|cyclonedx|vuln|custom) or an URI (default "custom")
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -t, --timeout duration     timeout for commands (default 3m0s)
  -d, --verbose              log debug output
```

### SEE ALSO

* [cosign](cosign.md)	 - A tool for Container Signing, Verification and Storage in an OCI registry.

