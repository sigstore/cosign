## cosign dockerfile verify

Verify a signature on the base image specified in the Dockerfile

### Synopsis

Verify signature and annotations on images in a Dockerfile by checking claims
against the transparency log.

Shell-like variables in the Dockerfile's FROM lines will be substituted with values from the OS ENV.

```
cosign dockerfile verify [flags]
```

### Examples

```
  cosign dockerfile verify --key <key path>|<key url>|<kms uri> <path/to/Dockerfile>

  # verify cosign claims and signing certificates on the FROM images in the Dockerfile
  cosign dockerfile verify <path/to/Dockerfile>

  # only verify the base image (the last FROM image)
  cosign dockerfile verify --base-image-only <path/to/Dockerfile>

  # additionally verify specified annotations
  cosign dockerfile verify -a key1=val1 -a key2=val2 <path/to/Dockerfile>

  # (experimental) additionally, verify with the transparency log
  COSIGN_EXPERIMENTAL=1 cosign dockerfile verify <path/to/Dockerfile>

  # verify images with public key
  cosign dockerfile verify --key cosign.pub <path/to/Dockerfile>

  # verify images with public key provided by URL
  cosign dockerfile verify --key https://host.for/<FILE> <path/to/Dockerfile>

  # verify images with public key stored in Azure Key Vault
  cosign dockerfile verify --key azurekms://[VAULT_NAME][VAULT_URI]/[KEY] <path/to/Dockerfile>

  # verify images with public key stored in AWS KMS
  cosign dockerfile verify --key awskms://[ENDPOINT]/[ID/ALIAS/ARN] <path/to/Dockerfile>

  # verify images with public key stored in Google Cloud KMS
  cosign dockerfile verify --key gcpkms://projects/[PROJECT]/locations/global/keyRings/[KEYRING]/cryptoKeys/[KEY] <path/to/Dockerfile>

  # verify images with public key stored in Hashicorp Vault
  cosign dockerfile verify --key hashivault://[KEY] <path/to/Dockerfile>
```

### Options

```
      --allow-http-registry                                                                      whether to allow using HTTP protocol while connecting to registries. Don't use this for anything but testing
      --allow-insecure-registry                                                                  whether to allow insecure connections to registries (e.g., with expired or self-signed TLS certificates). Don't use this for anything but testing
  -a, --annotations strings                                                                      extra key=value pairs to sign
      --attachment string                                                                        related image attachment to verify (sbom), default none
      --attachment-tag-prefix [AttachmentTagPrefix]sha256-[TargetImageDigest].[AttachmentName]   optional custom prefix to use for attached image tags. Attachment images are tagged as: [AttachmentTagPrefix]sha256-[TargetImageDigest].[AttachmentName]
      --base-image-only                                                                          only verify the base image (the last FROM image in the Dockerfile)
      --certificate string                                                                       path to the public certificate. The certificate will be verified against the Fulcio roots if the --certificate-chain option is not passed.
      --certificate-chain string                                                                 path to a list of CA certificates in PEM format which will be needed when building the certificate chain for the signing certificate. Must start with the parent intermediate CA certificate of the signing certificate and end with the root certificate
      --certificate-github-workflow-name string                                                  contains the workflow claim from the GitHub OIDC Identity token that contains the name of the executed workflow.
      --certificate-github-workflow-ref string                                                   contains the ref claim from the GitHub OIDC Identity token that contains the git ref that the workflow run was based upon.
      --certificate-github-workflow-repository string                                            contains the repository claim from the GitHub OIDC Identity token that contains the repository that the workflow run was based upon
      --certificate-github-workflow-sha string                                                   contains the sha claim from the GitHub OIDC Identity token that contains the commit SHA that the workflow run was based upon.
      --certificate-github-workflow-trigger string                                               contains the event_name claim from the GitHub OIDC Identity token that contains the name of the event that triggered the workflow run
      --certificate-identity string                                                              The identity expected in a valid Fulcio certificate. Valid values include email address, DNS names, IP addresses, and URIs. Either --certificate-identity or --certificate-identity-regexp must be set for keyless flows.
      --certificate-identity-regexp string                                                       A regular expression alternative to --certificate-identity. Accepts the Go regular expression syntax described at https://golang.org/s/re2syntax. Either --certificate-identity or --certificate-identity-regexp must be set for keyless flows.
      --certificate-oidc-issuer string                                                           The OIDC issuer expected in a valid Fulcio certificate, e.g. https://token.actions.githubusercontent.com or https://oauth2.sigstore.dev/auth. Either --certificate-oidc-issuer or --certificate-oidc-issuer-regexp must be set for keyless flows.
      --certificate-oidc-issuer-regexp string                                                    A regular expression alternative to --certificate-oidc-issuer. Accepts the Go regular expression syntax described at https://golang.org/s/re2syntax. Either --certificate-oidc-issuer or --certificate-oidc-issuer-regexp must be set for keyless flows.
      --check-claims                                                                             whether to check the claims found (default true)
  -h, --help                                                                                     help for verify
      --insecure-ignore-sct                                                                      when set, verification will not check that a certificate contains an embedded SCT, a proof of inclusion in a certificate transparency log
      --insecure-skip-tlog-verify                                                                skip transparency log verification, to be used when an artifact signature has not been uploaded to the transparency log. Artifacts cannot be publicly verified when not included in a log
      --k8s-keychain                                                                             whether to use the kubernetes keychain instead of the default keychain (supports workload identity).
      --key string                                                                               path to the public key file, KMS URI or Kubernetes Secret
      --local-image                                                                              whether the specified image is a path to an image saved locally via 'cosign save'
      --offline                                                                                  only allow offline verification
  -o, --output string                                                                            output format for the signing image information (json|text) (default "json")
      --rekor-url string                                                                         [EXPERIMENTAL] address of rekor STL server (default "https://rekor.sigstore.dev")
      --sct string                                                                               path to a detached Signed Certificate Timestamp, formatted as a RFC6962 AddChainResponse struct. If a certificate contains an SCT, verification will check both the detached and embedded SCTs.
      --signature string                                                                         signature content or path or remote URL
      --signature-digest-algorithm string                                                        digest algorithm to use when processing a signature (sha224|sha256|sha384|sha512) (default "sha256")
      --sk                                                                                       whether to use a hardware security key
      --slot string                                                                              security key slot to use for generated key (default: signature) (authentication|signature|card-authentication|key-management)
      --timestamp-certificate-chain string                                                       path to PEM-encoded certificate chain file for the RFC3161 timestamp authority. Must contain the root CA certificate. Optionally may contain intermediate CA certificates, and may contain the leaf TSA certificate if not present in the timestamp
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -t, --timeout duration     timeout for commands (default 3m0s)
  -d, --verbose              log debug output
```

### SEE ALSO

* [cosign dockerfile](cosign_dockerfile.md)	 - Provides utilities for discovering images in and performing operations on Dockerfiles

