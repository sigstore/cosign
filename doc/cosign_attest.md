## cosign attest

Attest the supplied container image.

```
cosign attest [flags]
```

### Examples

```
  cosign attest --key <key path>|<kms uri> [--predicate <path>] [--a key=value] [--no-upload=true|false] [--f] [--r] <image uri>

  # attach an attestation to a container image Google sign-in (experimental)
  COSIGN_EXPERIMENTAL=1 cosign attest --timeout 90s --predicate <FILE> --type <TYPE> <IMAGE>

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

  # attach an attestation to a container image which does not fully support OCI media types
  COSIGN_DOCKER_MEDIA_TYPES=1 cosign attest --predicate <FILE> --type <TYPE> --key cosign.key legacy-registry.example.com/my/image
```

### Options

```
      --allow-insecure-registry                                                                  whether to allow insecure connections to registries. Don't use this for anything but testing
      --attachment-tag-prefix [AttachmentTagPrefix]sha256-[TargetImageDigest].[AttachmentName]   optional custom prefix to use for attached image tags. Attachment images are tagged as: [AttachmentTagPrefix]sha256-[TargetImageDigest].[AttachmentName]
      --cert string                                                                              path to the x509 certificate to include in the Signature
  -f, --force                                                                                    skip warnings and confirmations
      --fulcio-url string                                                                        [EXPERIMENTAL] address of sigstore PKI server (default "https://v1.fulcio.sigstore.dev")
  -h, --help                                                                                     help for attest
      --identity-token string                                                                    [EXPERIMENTAL] identity token to use for certificate from fulcio
      --insecure-skip-verify                                                                     [EXPERIMENTAL] skip verifying fulcio published to the SCT (this should only be used for testing).
      --k8s-keychain                                                                             whether to use the kubernetes keychain instead of the default keychain (supports workload identity).
      --key string                                                                               path to the private key file, KMS URI or Kubernetes Secret
      --no-upload                                                                                do not upload the generated attestation
      --oidc-client-id string                                                                    [EXPERIMENTAL] OIDC client ID for application (default "sigstore")
      --oidc-client-secret string                                                                [EXPERIMENTAL] OIDC client secret for application
      --oidc-issuer string                                                                       [EXPERIMENTAL] OIDC provider to be used to issue ID token (default "https://oauth2.sigstore.dev/auth")
      --predicate string                                                                         path to the predicate file.
  -r, --recursive                                                                                if a multi-arch image is specified, additionally sign each discrete image
      --rekor-url string                                                                         [EXPERIMENTAL] address of rekor STL server (default "https://rekor.sigstore.dev")
      --replace                                                                                  
      --sk                                                                                       whether to use a hardware security key
      --slot string                                                                              security key slot to use for generated key (default: signature) (authentication|signature|card-authentication|key-management)
      --timeout duration                                                                         HTTP Timeout defaults to 30 seconds (default 30s)
      --type string                                                                              specify a predicate type (slsaprovenance|link|spdx|custom) or an URI (default "custom")
```

### Options inherited from parent commands

```
      --azure-container-registry-config string   Path to the file containing Azure container registry configuration information.
      --output-file string                       log output to a file
  -d, --verbose                                  log debug output
```

### SEE ALSO

* [cosign](cosign.md)	 - 

