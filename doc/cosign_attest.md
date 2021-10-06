## cosign attest

Attest the supplied container image.

```
cosign attest [flags]
```

### Examples

```
  cosign attest --key <key path>|<kms uri> [--predicate <path>] [--a key=value] [--upload=true|false] [--f] [--r] <image uri>

  # attach an attestation to a container image Google sign-in (experimental)
  COSIGN_EXPERIMENTAL=1 cosign attest --predicate <FILE> --type <TYPE> <IMAGE>

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
      --allow-insecure-registry   whether to allow insecure connections to registries. Don't use this for anything but testing
      --cert string               path to the x509 certificate to include in the Signature
  -f, --force                     skip warnings and confirmations
      --fulcio-url string         [EXPERIMENTAL] address of sigstore PKI server (default "https://fulcio.sigstore.dev")
  -h, --help                      help for attest
      --identity-token string     [EXPERIMENTAL] identity token to use for certificate from fulcio
      --key string                path to the private key file, KMS URI or Kubernetes Secret
      --predicate string          path to the predicate file.
  -r, --recursive                 if a multi-arch image is specified, additionally sign each discrete image
      --rekor-url string          [EXPERIMENTAL] address of rekor STL server (default "https://rekor.sigstore.dev")
      --sk                        whether to use a hardware security key
      --slot string               security key slot to use for generated key (default: signature) (authentication|signature|card-authentication|key-management)
      --type string               specify a predicate type (slsaprovenance|link|spdx|custom) or an URI (default "custom")
      --upload                    whether to upload the signature (default true)
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -d, --verbose              log debug output
```

### SEE ALSO

* [cosign](cosign.md)	 - 

