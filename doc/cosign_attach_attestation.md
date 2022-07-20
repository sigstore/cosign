## cosign attach attestation

Attach attestation to the supplied container image

```
cosign attach attestation [flags]
```

### Examples

```
  cosign attach attestation --attestation <payload path> <image uri>

  # attach multiple attestations to a container image
  cosign attach attestation --attestation <payload path> --attestation <payload path> <image uri>
```

### Options

```
      --allow-insecure-registry                                                                  whether to allow insecure connections to registries. Don't use this for anything but testing
      --attachment-tag-prefix [AttachmentTagPrefix]sha256-[TargetImageDigest].[AttachmentName]   optional custom prefix to use for attached image tags. Attachment images are tagged as: [AttachmentTagPrefix]sha256-[TargetImageDigest].[AttachmentName]
      --attestation stringArray                                                                  path to the attestation envelope
  -h, --help                                                                                     help for attestation
      --k8s-keychain                                                                             whether to use the kubernetes keychain instead of the default keychain (supports workload identity).
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -t, --timeout duration     timeout for commands (default 3m0s)
  -d, --verbose              log debug output
```

### SEE ALSO

* [cosign attach](cosign_attach.md)	 - Provides utilities for attaching artifacts to other artifacts in a registry

