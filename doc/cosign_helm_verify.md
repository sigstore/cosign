## cosign helm verify

verify container images managed by Helm Chart

### Synopsis

Allows you to sign container images managed by Helm Chart

```
cosign helm verify [flags]
```

### Examples

```


```

### Options

```
      --allow-insecure-registry                                                                  whether to allow insecure connections to registries. Don't use this for anything but testing
  -a, --annotations strings                                                                      extra key=value pairs to sign
      --attachment string                                                                        related image attachment to sign (sbom), default none
      --attachment-tag-prefix [AttachmentTagPrefix]sha256-[TargetImageDigest].[AttachmentName]   optional custom prefix to use for attached image tags. Attachment images are tagged as: [AttachmentTagPrefix]sha256-[TargetImageDigest].[AttachmentName]
      --cert string                                                                              path to the public certificate
      --cert-email string                                                                        the email expected in a valid fulcio cert
      --check-claims                                                                             whether to check the claims found (default true)
  -h, --help                                                                                     help for verify
      --k8s-keychain                                                                             whether to use the kubernetes keychain instead of the default keychain (supports workload identity).
      --key string                                                                               path to the public key file, KMS URI or Kubernetes Secret
  -o, --output string                                                                            output format for the signing image information (json|text) (default "json")
      --rekor-url string                                                                         [EXPERIMENTAL] address of rekor STL server (default "https://rekor.sigstore.dev")
      --signature string                                                                         signature content or path or remote URL
      --signature-digest-algorithm string                                                        digest algorithm to use when processing a signature (sha224|sha256|sha384|sha512) (default "sha256")
      --sk                                                                                       whether to use a hardware security key
      --slot string                                                                              security key slot to use for generated key (default: signature) (authentication|signature|card-authentication|key-management)
```

### Options inherited from parent commands

```
      --azure-container-registry-config string   Path to the file containing Azure container registry configuration information.
      --output-file string                       log output to a file
  -d, --verbose                                  log debug output
```

### SEE ALSO

* [cosign helm](cosign_helm.md)	 - Provides utilities for discovering images in and performing operations on Helm Charts

