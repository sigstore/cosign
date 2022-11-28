## cosign download attestation

Download in-toto attestations from the supplied container image

```
cosign download attestation [flags]
```

### Examples

```
  cosign download attestation <image uri> [--predicate-type]
```

### Options

```
      --allow-http-registry                                                                      whether to allow using HTTP protocol while connecting to registries. Don't use this for anything but testing
      --allow-insecure-registry                                                                  whether to allow insecure connections to registries (e.g., with expired or self-signed TLS certificates). Don't use this for anything but testing
      --attachment-tag-prefix [AttachmentTagPrefix]sha256-[TargetImageDigest].[AttachmentName]   optional custom prefix to use for attached image tags. Attachment images are tagged as: [AttachmentTagPrefix]sha256-[TargetImageDigest].[AttachmentName]
  -h, --help                                                                                     help for attestation
      --k8s-keychain                                                                             whether to use the kubernetes keychain instead of the default keychain (supports workload identity).
      --predicate-type string                                                                    download attestation matching supplied predicate type
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -t, --timeout duration     timeout for commands (default 3m0s)
  -d, --verbose              log debug output
```

### SEE ALSO

* [cosign download](cosign_download.md)	 - Provides utilities for downloading artifacts and attached artifacts in a registry

