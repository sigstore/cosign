## cosign triangulate

Outputs the located cosign image reference. This is the location cosign stores the specified artifact type.

```
cosign triangulate [flags]
```

### Examples

```
  cosign triangulate <IMAGE>
```

### Options

```
      --allow-insecure-registry                                                                  whether to allow insecure connections to registries. Don't use this for anything but testing
      --attachment-tag-prefix [AttachmentTagPrefix]sha256-[TargetImageDigest].[AttachmentName]   optional custom prefix to use for attached image tags. Attachment images are tagged as: [AttachmentTagPrefix]sha256-[TargetImageDigest].[AttachmentName]
  -h, --help                                                                                     help for triangulate
      --k8s-keychain                                                                             whether to use the kubernetes keychain instead of the default keychain (supports workload identity).
      --type string                                                                              related attachment to triangulate (attestation|sbom|signature), default signature (default "signature")
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -d, --verbose              log debug output
```

### SEE ALSO

* [cosign](cosign.md)	 - 

