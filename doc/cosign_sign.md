## cosign sign

Sign the supplied container image.

### Synopsis

Sign the supplied container image.

Make sure to sign the image by its digest (@sha256:...) rather than by tag
(:latest) so that you actually sign what you think you're signing! This prevents
race conditions or (worse) malicious tampering.


```
cosign sign [flags]
```

### Examples

```
  cosign sign --key <key path>|<kms uri> [--payload <path>] [-a key=value] [--upload=true|false] [-f] [-r] <image digest uri>

  # sign a container image with the Sigstore OIDC flow
  cosign sign <IMAGE DIGEST>

  # sign a container image with a local key pair file
  cosign sign --key cosign.key <IMAGE DIGEST>

  # sign a multi-arch container image AND all referenced, discrete images
  cosign sign --key cosign.key --recursive <MULTI-ARCH IMAGE DIGEST>

  # sign a container image and add annotations
  cosign sign --key cosign.key -a key1=value1 -a key2=value2 <IMAGE DIGEST>

  # sign a container image with a key stored in an environment variable
  cosign sign --key env://[ENV_VAR] <IMAGE DIGEST>

  # sign a container image with a key pair stored in Azure Key Vault
  cosign sign --key azurekms://[VAULT_NAME][VAULT_URI]/[KEY] <IMAGE DIGEST>

  # sign a container image with a key pair stored in AWS KMS
  cosign sign --key awskms://[ENDPOINT]/[ID/ALIAS/ARN] <IMAGE DIGEST>

  # sign a container image with a key pair stored in Google Cloud KMS
  cosign sign --key gcpkms://projects/[PROJECT]/locations/global/keyRings/[KEYRING]/cryptoKeys/[KEY]/versions/[VERSION] <IMAGE DIGEST>

  # sign a container image with a key pair stored in Hashicorp Vault
  cosign sign --key hashivault://[KEY] <IMAGE DIGEST>

  # sign a container image with a key pair stored in a Kubernetes secret
  cosign sign --key k8s://[NAMESPACE]/[KEY] <IMAGE DIGEST>

  # sign a container image with a key, attaching a certificate and certificate chain
  cosign sign --key cosign.key --cert cosign.crt --cert-chain chain.crt <IMAGE DIGEST>

  # sign a container in a registry which does not fully support OCI media types
  COSIGN_DOCKER_MEDIA_TYPES=1 cosign sign --key cosign.key legacy-registry.example.com/my/image@<DIGEST>

  # sign a container image and upload to the transparency log
  cosign sign --key cosign.key <IMAGE DIGEST>

  # sign a container image and skip uploading to the transparency log
  cosign sign --key cosign.key --tlog-upload=false <IMAGE DIGEST>

  # sign a container image by manually setting the container image identity
  cosign sign --sign-container-identity <NEW IMAGE DIGEST> <IMAGE DIGEST>

  # sign a container image and honor the creation timestamp of the signature
  cosign sign --key cosign.key --record-creation-timestamp <IMAGE DIGEST>
```

### Options

```
      --allow-http-registry                                                                      whether to allow using HTTP protocol while connecting to registries. Don't use this for anything but testing
      --allow-insecure-registry                                                                  whether to allow insecure connections to registries (e.g., with expired or self-signed TLS certificates). Don't use this for anything but testing
  -a, --annotations strings                                                                      extra key=value pairs to sign
      --attachment string                                                                        DEPRECATED, related image attachment to sign (sbom), default none
      --attachment-tag-prefix [AttachmentTagPrefix]sha256-[TargetImageDigest].[AttachmentName]   optional custom prefix to use for attached image tags. Attachment images are tagged as: [AttachmentTagPrefix]sha256-[TargetImageDigest].[AttachmentName]
      --bundle string                                                                            write everything required to verify the image to FILE
      --certificate string                                                                       path to the X.509 certificate in PEM format to include in the OCI Signature
      --certificate-chain string                                                                 path to a list of CA X.509 certificates in PEM format which will be needed when building the certificate chain for the signing certificate. Must start with the parent intermediate CA certificate of the signing certificate and end with the root certificate. Included in the OCI Signature
      --fulcio-auth-flow string                                                                  fulcio interactive oauth2 flow to use for certificate from fulcio. Defaults to determining the flow based on the runtime environment. (options) normal|device|token|client_credentials
      --fulcio-url string                                                                        address of sigstore PKI server (default "https://fulcio.sigstore.dev")
  -h, --help                                                                                     help for sign
      --identity-token string                                                                    identity token to use for certificate from fulcio. the token or a path to a file containing the token is accepted.
      --insecure-skip-verify                                                                     skip verifying fulcio published to the SCT (this should only be used for testing).
      --issue-certificate                                                                        issue a code signing certificate from Fulcio, even if a key is provided
      --k8s-keychain                                                                             whether to use the kubernetes keychain instead of the default keychain (supports workload identity).
      --key string                                                                               path to the private key file, KMS URI or Kubernetes Secret
      --new-bundle-format                                                                        expect the signature/attestation to be packaged in a Sigstore bundle (default true)
      --oidc-client-id string                                                                    OIDC client ID for application (default "sigstore")
      --oidc-client-secret-file string                                                           Path to file containing OIDC client secret for application
      --oidc-disable-ambient-providers                                                           Disable ambient OIDC providers. When true, ambient credentials will not be read
      --oidc-issuer string                                                                       OIDC provider to be used to issue ID token (default "https://oauth2.sigstore.dev/auth")
      --oidc-provider string                                                                     Specify the provider to get the OIDC token from (Optional). If unset, all options will be tried. Options include: [spiffe, google, github-actions, filesystem, buildkite-agent]
      --oidc-redirect-url string                                                                 OIDC redirect URL (Optional). The default oidc-redirect-url is 'http://localhost:0/auth/callback'.
      --output-certificate string                                                                write the certificate to FILE
      --output-payload string                                                                    write the signed payload to FILE
      --output-signature string                                                                  write the signature to FILE
      --payload string                                                                           path to a payload file to use rather than generating one
      --record-creation-timestamp                                                                set the createdAt timestamp in the signature artifact to the time it was created; by default, cosign sets this to the zero value
  -r, --recursive                                                                                if a multi-arch image is specified, additionally sign each discrete image
      --registry-cacert string                                                                   path to the X.509 CA certificate file in PEM format to be used for the connection to the registry
      --registry-client-cert string                                                              path to the X.509 certificate file in PEM format to be used for the connection to the registry
      --registry-client-key string                                                               path to the X.509 private key file in PEM format to be used, together with the 'registry-client-cert' value, for the connection to the registry
      --registry-password string                                                                 registry basic auth password
      --registry-referrers-mode registryReferrersMode                                            mode for fetching references from the registry. allowed: legacy, oci-1-1
      --registry-server-name string                                                              SAN name to use as the 'ServerName' tls.Config field to verify the mTLS connection to the registry
      --registry-token string                                                                    registry bearer auth token
      --registry-username string                                                                 registry basic auth username
      --rekor-url string                                                                         address of rekor STL server (default "https://rekor.sigstore.dev")
      --rekor-version uint32                                                                     version of rekor API (default 1)
      --sign-container-identity strings                                                          manually set the .critical.docker-reference field for the signed identity, which is useful when image proxies are being used where the pull reference should match the signature, this flag is comma delimited. ex: --sign-container-identity=identity1,identity2
      --signing-config string                                                                    path to a signing config file. Must provide --new-bundle-format, which will store verification material in the new format
      --sk                                                                                       whether to use a hardware security key
      --slot string                                                                              security key slot to use for generated key (default: signature) (authentication|signature|card-authentication|key-management)
      --timestamp-client-cacert string                                                           path to the X.509 CA certificate file in PEM format to be used for the connection to the TSA Server
      --timestamp-client-cert string                                                             path to the X.509 certificate file in PEM format to be used for the connection to the TSA Server
      --timestamp-client-key string                                                              path to the X.509 private key file in PEM format to be used, together with the 'timestamp-client-cert' value, for the connection to the TSA Server
      --timestamp-server-name string                                                             SAN name to use as the 'ServerName' tls.Config field to verify the mTLS connection to the TSA Server
      --timestamp-server-url string                                                              url to the Timestamp RFC3161 server, default none. Must be the path to the API to request timestamp responses, e.g. https://freetsa.org/tsr
      --trusted-root string                                                                      optional path to a TrustedRoot JSON file to verify a signature after signing
      --upload                                                                                   whether to upload the signature (default true)
      --use-signing-config                                                                       whether to use a TUF-provided signing config for the service URLs. Must set --new-bundle-format, which will store verification material in the new format (default true)
  -y, --yes                                                                                      skip confirmation prompts for non-destructive operations
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -t, --timeout duration     timeout for commands (default 3m0s)
  -d, --verbose              log debug output
```

### SEE ALSO

* [cosign](cosign.md)	 - A tool for Container Signing, Verification and Storage in an OCI registry.

