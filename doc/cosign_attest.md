## cosign attest

Attest the supplied container image.

```
cosign attest [flags]
```

### Examples

```
  cosign attest --key <key path>|<kms uri> [--predicate <path>] [--a key=value] [--no-upload=true|false] [--record-creation-timestamp=true|false] [--f] [--r] <image uri>

  # attach an attestation to a container image Google sign-in
  cosign attest --timeout 90s --predicate <FILE> --type <TYPE> <IMAGE>

  # attach an attestation to a container image with a local key pair file
  cosign attest --predicate <FILE> --type <TYPE> --key cosign.key <IMAGE>

  # attach an attestation to a container image with a key pair stored in Azure Key Vault
  cosign attest --predicate <FILE> --type <TYPE> --key azurekms://[VAULT_NAME][VAULT_URI]/[KEY] <IMAGE>

  # attach an attestation to a container image with a key pair stored in AWS KMS
  cosign attest --predicate <FILE> --type <TYPE> --key awskms://[ENDPOINT]/[ID/ALIAS/ARN] <IMAGE>

  # attach an attestation to a container image with a key pair stored in Google Cloud KMS
  cosign attest --predicate <FILE> --type <TYPE> --key gcpkms://projects/[PROJECT]/locations/global/keyRings/[KEYRING]/cryptoKeys/[KEY]/versions/[VERSION] <IMAGE>

  # attach an attestation to a container image with a key pair stored in Hashicorp Vault
  cosign attest --predicate <FILE> --type <TYPE> --key hashivault://[KEY] <IMAGE>

  # attach an attestation to a container image with a local key pair file, including a certificate and certificate chain
  cosign attest --predicate <FILE> --type <TYPE> --key cosign.key --cert cosign.crt --cert-chain chain.crt <IMAGE>

  # attach an attestation to a container image which does not fully support OCI media types
  COSIGN_DOCKER_MEDIA_TYPES=1 cosign attest --predicate <FILE> --type <TYPE> --key cosign.key legacy-registry.example.com/my/image

  # supply attestation via stdin
  echo <PAYLOAD> | cosign attest --predicate - <IMAGE>

  # attach an attestation to a container image and honor the creation timestamp of the signature
  cosign attest --predicate <FILE> --type <TYPE> --key cosign.key --record-creation-timestamp <IMAGE>
```

### Options

```
      --allow-http-registry                                                                      whether to allow using HTTP protocol while connecting to registries. Don't use this for anything but testing
      --allow-insecure-registry                                                                  whether to allow insecure connections to registries (e.g., with expired or self-signed TLS certificates). Don't use this for anything but testing
      --attachment-tag-prefix [AttachmentTagPrefix]sha256-[TargetImageDigest].[AttachmentName]   optional custom prefix to use for attached image tags. Attachment images are tagged as: [AttachmentTagPrefix]sha256-[TargetImageDigest].[AttachmentName]
      --certificate string                                                                       path to the X.509 certificate in PEM format to include in the OCI Signature
      --certificate-chain string                                                                 path to a list of CA X.509 certificates in PEM format which will be needed when building the certificate chain for the signing certificate. Must start with the parent intermediate CA certificate of the signing certificate and end with the root certificate. Included in the OCI Signature
      --fulcio-auth-flow string                                                                  fulcio interactive oauth2 flow to use for certificate from fulcio. Defaults to determining the flow based on the runtime environment. (options) normal|device|token|client_credentials
      --fulcio-url string                                                                        address of sigstore PKI server (default "https://fulcio.sigstore.dev")
  -h, --help                                                                                     help for attest
      --identity-token string                                                                    identity token to use for certificate from fulcio. the token or a path to a file containing the token is accepted.
      --insecure-skip-verify                                                                     skip verifying fulcio published to the SCT (this should only be used for testing).
      --k8s-keychain                                                                             whether to use the kubernetes keychain instead of the default keychain (supports workload identity).
      --key string                                                                               path to the private key file, KMS URI or Kubernetes Secret
      --no-upload                                                                                do not upload the generated attestation
      --oidc-client-id string                                                                    OIDC client ID for application (default "sigstore")
      --oidc-client-secret-file string                                                           Path to file containing OIDC client secret for application
      --oidc-disable-ambient-providers                                                           Disable ambient OIDC providers. When true, ambient credentials will not be read
      --oidc-issuer string                                                                       OIDC provider to be used to issue ID token (default "https://oauth2.sigstore.dev/auth")
      --oidc-provider string                                                                     Specify the provider to get the OIDC token from (Optional). If unset, all options will be tried. Options include: [spiffe, google, github-actions, filesystem, buildkite-agent]
      --oidc-redirect-url string                                                                 OIDC redirect URL (Optional). The default oidc-redirect-url is 'http://localhost:0/auth/callback'.
      --predicate string                                                                         path to the predicate file.
      --record-creation-timestamp                                                                set the createdAt timestamp in the attestation artifact to the time it was created; by default, cosign sets this to the zero value
  -r, --recursive                                                                                if a multi-arch image is specified, additionally sign each discrete image
      --registry-cacert string                                                                   path to the X.509 CA certificate file in PEM format to be used for the connection to the registry
      --registry-client-cert string                                                              path to the X.509 certificate file in PEM format to be used for the connection to the registry
      --registry-client-key string                                                               path to the X.509 private key file in PEM format to be used, together with the 'registry-client-cert' value, for the connection to the registry
      --registry-password string                                                                 registry basic auth password
      --registry-server-name string                                                              SAN name to use as the 'ServerName' tls.Config field to verify the mTLS connection to the registry
      --registry-token string                                                                    registry bearer auth token
      --registry-username string                                                                 registry basic auth username
      --rekor-entry-type string                                                                  specifies the type to be used for a rekor entry upload. Options are intoto or dsse (default).  (default "dsse")
      --rekor-url string                                                                         address of rekor STL server (default "https://rekor.sigstore.dev")
      --replace                                                                                  
      --sk                                                                                       whether to use a hardware security key
      --slot string                                                                              security key slot to use for generated key (default: signature) (authentication|signature|card-authentication|key-management)
      --timestamp-server-url string                                                              url to the Timestamp RFC3161 server, default none. Must be the path to the API to request timestamp responses, e.g. https://freetsa.org/tsr
      --tlog-upload                                                                              whether or not to upload to the tlog (default true)
      --type string                                                                              specify a predicate type (slsaprovenance|slsaprovenance02|slsaprovenance1|link|spdx|spdxjson|cyclonedx|vuln|openvex|custom) or an URI (default "custom")
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

