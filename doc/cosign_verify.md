## cosign verify

Verify a signature on the supplied container image

### Synopsis

Verify signature and annotations on an image by checking the claims
against the transparency log.

```
cosign verify [flags]
```

### Examples

```
  cosign verify --key <key path>|<key url>|<kms uri> <image uri> [<image uri> ...]

  # verify cosign claims and signing certificates on the image with the transparency log
  cosign verify <IMAGE>

  # verify multiple images
  cosign verify <IMAGE_1> <IMAGE_2> ...

  # additionally verify specified annotations
  cosign verify -a key1=val1 -a key2=val2 <IMAGE>

  # verify image with an on-disk public key
  cosign verify --key cosign.pub <IMAGE>

  # verify image with an on-disk public key, manually specifying the
  # signature digest algorithm
  cosign verify --key cosign.pub --signature-digest-algorithm sha512 <IMAGE>

  # verify image with an on-disk signed image from 'cosign save'
  cosign verify --key cosign.pub --local-image <PATH>

  # verify image with local certificate and certificate chain
  cosign verify --cert cosign.crt --cert-chain chain.crt <IMAGE>

  # verify image with public key provided by URL
  cosign verify --key https://host.for/[FILE] <IMAGE>

  # verify image with a key stored in an environment variable
  cosign verify --key env://[ENV_VAR] <IMAGE>

  # verify image with public key stored in Google Cloud KMS
  cosign verify --key gcpkms://projects/[PROJECT]/locations/global/keyRings/[KEYRING]/cryptoKeys/[KEY] <IMAGE>

  # verify image with public key stored in Hashicorp Vault
  cosign verify --key hashivault://[KEY] <IMAGE>

  # verify image with public key stored in a Kubernetes secret
  cosign verify --key k8s://[NAMESPACE]/[KEY] <IMAGE>

  # verify image with public key stored in GitLab with project name
  cosign verify --key gitlab://[OWNER]/[PROJECT_NAME] <IMAGE>

  # verify image with public key stored in GitLab with project id
  cosign verify --key gitlab://[PROJECT_ID] <IMAGE>
```

### Options

```
      --allow-http-registry                                                                      whether to allow using HTTP protocol while connecting to registries. Don't use this for anything but testing
      --allow-insecure-registry                                                                  whether to allow insecure connections to registries (e.g., with expired or self-signed TLS certificates). Don't use this for anything but testing
  -a, --annotations strings                                                                      extra key=value pairs to sign
      --attachment string                                                                        related image attachment to verify (sbom), default none
      --attachment-tag-prefix [AttachmentTagPrefix]sha256-[TargetImageDigest].[AttachmentName]   optional custom prefix to use for attached image tags. Attachment images are tagged as: [AttachmentTagPrefix]sha256-[TargetImageDigest].[AttachmentName]
      --certificate string                                                                       path to the public certificate. The certificate will be verified against the Fulcio roots if the --certificate-chain option is not passed.
      --certificate-chain string                                                                 path to a list of CA certificates in PEM format which will be needed when building the certificate chain for the signing certificate. Must start with the parent intermediate CA certificate of the signing certificate and end with the root certificate
      --certificate-email string                                                                 DEPRECATED: Use --certificate-identity instead. The email expected in a valid Fulcio certificate
      --certificate-github-workflow-name string                                                  contains the workflow claim from the GitHub OIDC Identity token that contains the name of the executed workflow.
      --certificate-github-workflow-ref string                                                   contains the ref claim from the GitHub OIDC Identity token that contains the git ref that the workflow run was based upon.
      --certificate-github-workflow-repository string                                            contains the repository claim from the GitHub OIDC Identity token that contains the repository that the workflow run was based upon
      --certificate-github-workflow-sha string                                                   contains the sha claim from the GitHub OIDC Identity token that contains the commit SHA that the workflow run was based upon.
      --certificate-github-workflow-trigger string                                               contains the event_name claim from the GitHub OIDC Identity token that contains the name of the event that triggered the workflow run
      --certificate-identity string                                                              Required. The identity expected in a valid Fulcio certificate. Valid values include email address, DNS names, IP addresses, and URIs.
      --certificate-oidc-issuer string                                                           Required. The OIDC issuer expected in a valid Fulcio certificate, e.g. https://token.actions.githubusercontent.com or https://oauth2.sigstore.dev/auth
      --check-claims                                                                             whether to check the claims found (default true)
      --enforce-sct                                                                              whether to enforce that a certificate contain an embedded SCT, a proof of inclusion in a certificate transparency log
  -h, --help                                                                                     help for verify
      --k8s-keychain                                                                             whether to use the kubernetes keychain instead of the default keychain (supports workload identity).
      --key string                                                                               path to the public key file, KMS URI or Kubernetes Secret
      --local-image                                                                              whether the specified image is a path to an image saved locally via 'cosign save'
  -o, --output string                                                                            output format for the signing image information (json|text) (default "json")
      --rekor-url string                                                                         [EXPERIMENTAL] address of rekor STL server (default "https://rekor.sigstore.dev")
      --signature string                                                                         signature content or path or remote URL
      --signature-digest-algorithm string                                                        digest algorithm to use when processing a signature (sha224|sha256|sha384|sha512) (default "sha256")
      --sk                                                                                       whether to use a hardware security key
      --slot string                                                                              security key slot to use for generated key (default: signature) (authentication|signature|card-authentication|key-management)
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -t, --timeout duration     timeout for commands (default 3m0s)
  -d, --verbose              log debug output
```

### SEE ALSO

* [cosign](cosign.md)	 - A tool for Container Signing, Verification and Storage in an OCI registry.

