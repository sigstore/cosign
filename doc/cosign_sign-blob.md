## cosign sign-blob

Sign the supplied blob, outputting the base64-encoded signature to stdout.

```
cosign sign-blob [flags]
```

### Examples

```
  cosign sign-blob --key <key path>|<kms uri> <blob>

  # sign a blob with Google sign-in (experimental)
  COSIGN_EXPERIMENTAL=1 cosign --timeout 90s sign-blob <FILE>

  # sign a blob with a local key pair file
  cosign sign-blob --key cosign.key <FILE>

  # sign a blob with a key pair stored in Azure Key Vault
  cosign sign-blob --key azurekms://[VAULT_NAME][VAULT_URI]/[KEY] <FILE>

  # sign a blob with a key pair stored in AWS KMS
  cosign sign-blob --key awskms://[ENDPOINT]/[ID/ALIAS/ARN] <FILE>

  # sign a blob with a key pair stored in Google Cloud KMS
  cosign sign-blob --key gcpkms://projects/[PROJECT]/locations/global/keyRings/[KEYRING]/cryptoKeys/[KEY] <FILE>

  # sign a blob with a key pair stored in Hashicorp Vault
  cosign sign-blob --key hashivault://[KEY] <FILE>
```

### Options

```
      --allow-insecure-registry                                                                  whether to allow insecure connections to registries. Don't use this for anything but testing
      --attachment-tag-prefix [AttachmentTagPrefix]sha256-[TargetImageDigest].[AttachmentName]   optional custom prefix to use for attached image tags. Attachment images are tagged as: [AttachmentTagPrefix]sha256-[TargetImageDigest].[AttachmentName]
      --b64                                                                                      whether to base64 encode the output (default true)
      --bundle string                                                                            write everything required to verify the blob to a FILE
      --fulcio-url string                                                                        [EXPERIMENTAL] address of sigstore PKI server (default "https://fulcio.sigstore.dev")
  -h, --help                                                                                     help for sign-blob
      --identity-token string                                                                    [EXPERIMENTAL] identity token to use for certificate from fulcio
      --insecure-skip-verify                                                                     [EXPERIMENTAL] skip verifying fulcio published to the SCT (this should only be used for testing).
      --k8s-keychain                                                                             whether to use the kubernetes keychain instead of the default keychain (supports workload identity).
      --key string                                                                               path to the private key file, KMS URI or Kubernetes Secret
      --oidc-client-id string                                                                    [EXPERIMENTAL] OIDC client ID for application (default "sigstore")
      --oidc-client-secret string                                                                [EXPERIMENTAL] OIDC client secret for application
      --oidc-issuer string                                                                       [EXPERIMENTAL] OIDC provider to be used to issue ID token (default "https://oauth2.sigstore.dev/auth")
      --oidc-redirect-uri string                                                                 [EXPERIMENTAL] OIDC redirect URI
      --output string                                                                            write the signature to FILE
      --output-certificate string                                                                write the certificate to FILE
      --output-signature string                                                                  write the signature to FILE
      --rekor-url string                                                                         [EXPERIMENTAL] address of rekor STL server (default "https://rekor.sigstore.dev")
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

