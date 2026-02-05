## cosign manifest verify

Verify all signatures of images specified in the manifest

### Synopsis

Verify all signature of images in a Kubernetes resource manifest by checking claims
against the transparency log.

```
cosign manifest verify [flags]
```

### Examples

```
  cosign manifest verify --key <key path>|<key url>|<kms uri> <path/to/manifest>

  # verify cosign claims and signing certificates on images in the manifest
  cosign manifest verify <path/to/my-deployment.yaml>

  # additionally verify specified annotations
  cosign manifest verify -a key1=val1 -a key2=val2 <path/to/my-deployment.yaml>

  # verify images with public key
  cosign manifest verify --key cosign.pub <path/to/my-deployment.yaml>

  # verify images with public key provided by URL
  cosign manifest verify --key https://host.for/<FILE> <path/to/my-deployment.yaml>

  # verify images with public key stored in Azure Key Vault
  cosign manifest verify --key azurekms://[VAULT_NAME][VAULT_URI]/[KEY] <path/to/my-deployment.yaml>

  # verify images with public key stored in AWS KMS
  cosign manifest verify --key awskms://[ENDPOINT]/[ID/ALIAS/ARN] <path/to/my-deployment.yaml>

  # verify images with public key stored in Google Cloud KMS
  cosign manifest verify --key gcpkms://projects/[PROJECT]/locations/global/keyRings/[KEYRING]/cryptoKeys/[KEY] <path/to/my-deployment.yaml>

  # verify images with public key stored in Hashicorp Vault
  cosign manifest verify --key hashivault://[KEY] <path/to/my-deployment.yaml>
```

### Options

```
      --allow-http-registry                                                                      whether to allow using HTTP protocol while connecting to registries. Don't use this for anything but testing
      --allow-insecure-registry                                                                  whether to allow insecure connections to registries (e.g., with expired or self-signed TLS certificates). Don't use this for anything but testing
  -a, --annotations strings                                                                      extra key=value pairs to sign
      --attachment string                                                                        DEPRECATED, related image attachment to verify (sbom), default none
      --attachment-tag-prefix [AttachmentTagPrefix]sha256-[TargetImageDigest].[AttachmentName]   optional custom prefix to use for attached image tags. Attachment images are tagged as: [AttachmentTagPrefix]sha256-[TargetImageDigest].[AttachmentName]
      --ca-intermediates string                                                                  path to a file of intermediate CA certificates in PEM format which will be needed when building the certificate chains for the signing certificate. The flag is optional and must be used together with --ca-roots, conflicts with --certificate-chain.
      --ca-roots string                                                                          path to a bundle file of CA certificates in PEM format which will be needed when building the certificate chains for the signing certificate. Conflicts with --certificate-chain.
      --certificate string                                                                       path to the public certificate. The certificate will be verified against the Fulcio roots if the --certificate-chain option is not passed.
      --certificate-chain string                                                                 path to a list of CA certificates in PEM format which will be needed when building the certificate chain for the signing certificate. Must start with the parent intermediate CA certificate of the signing certificate and end with the root certificate. Conflicts with --ca-roots and --ca-intermediates.
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
      --experimental-oci11                                                                       set to true to enable experimental OCI 1.1 behaviour (unrelated to bundle format)
  -h, --help                                                                                     help for verify
      --insecure-ignore-sct                                                                      when set, verification will not check that a certificate contains an embedded SCT, a proof of inclusion in a certificate transparency log
      --insecure-ignore-tlog                                                                     ignore transparency log verification, to be used when an artifact signature has not been uploaded to the transparency log. Artifacts cannot be publicly verified when not included in a log
      --k8s-keychain                                                                             whether to use the kubernetes keychain instead of the default keychain (supports workload identity).
      --key string                                                                               path to the public key file, KMS URI or Kubernetes Secret
      --local-image                                                                              whether the specified image is a path to an image saved locally via 'cosign save'
      --max-workers int                                                                          the amount of maximum workers for parallel executions (default 10)
      --new-bundle-format                                                                        expect the signature/attestation to be packaged in a Sigstore bundle (default true)
  -o, --output string                                                                            output format for the signing image information (json|text) (default "json")
      --payload string                                                                           payload path or remote URL
      --private-infrastructure                                                                   skip transparency log verification when verifying artifacts in a privately deployed infrastructure
      --registry-cacert string                                                                   path to the X.509 CA certificate file in PEM format to be used for the connection to the registry
      --registry-client-cert string                                                              path to the X.509 certificate file in PEM format to be used for the connection to the registry
      --registry-client-key string                                                               path to the X.509 private key file in PEM format to be used, together with the 'registry-client-cert' value, for the connection to the registry
      --registry-password string                                                                 registry basic auth password
      --registry-server-name string                                                              SAN name to use as the 'ServerName' tls.Config field to verify the mTLS connection to the registry
      --registry-token string                                                                    registry bearer auth token
      --registry-username string                                                                 registry basic auth username
      --rekor-url string                                                                         address of rekor STL server (default "https://rekor.sigstore.dev")
      --rekor-version uint32                                                                     version of rekor API (default 1)
      --sct string                                                                               path to a detached Signed Certificate Timestamp, formatted as a RFC6962 AddChainResponse struct. If a certificate contains an SCT, verification will check both the detached and embedded SCTs.
      --signature string                                                                         signature content or path or remote URL
      --signature-digest-algorithm string                                                        digest algorithm to use when processing a signature (sha224|sha256|sha384|sha512) (default "sha256")
      --sk                                                                                       whether to use a hardware security key
      --slot string                                                                              security key slot to use for generated key (default: signature) (authentication|signature|card-authentication|key-management)
      --timestamp-certificate-chain string                                                       path to PEM-encoded certificate chain file for the RFC3161 timestamp authority. Must contain the root CA certificate. Optionally may contain intermediate CA certificates, and may contain the leaf TSA certificate if not present in the timestamp
      --trusted-root string                                                                      Path to a Sigstore TrustedRoot JSON file. Requires --new-bundle-format to be set.
      --use-signed-timestamps                                                                    verify rfc3161 timestamps
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -t, --timeout duration     timeout for commands (default 3m0s)
  -d, --verbose              log debug output
```

### SEE ALSO

* [cosign manifest](cosign_manifest.md)	 - Provides utilities for discovering images in and performing operations on Kubernetes manifests

