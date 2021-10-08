## cosign attach sbom

Attach sbom to the supplied container image

```
cosign attach sbom [flags]
```

### Examples

```
  cosign attach sbom <image uri>
```

### Options

```
      --allow-insecure-registry                                                                  whether to allow insecure connections to registries. Don't use this for anything but testing
      --attachment-tag-prefix [AttachmentTagPrefix]sha256-[TargetImageDigest].[AttachmentName]   optional custom prefix to use for attached image tags. Attachment images are tagged as: [AttachmentTagPrefix]sha256-[TargetImageDigest].[AttachmentName]
  -h, --help                                                                                     help for sbom
      --sbom string                                                                              path to the sbom, or {-} for stdin
      --type string                                                                              type of sbom (spdx|cyclonedx) (default "spdx")
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -d, --verbose              log debug output
```

### SEE ALSO

* [cosign attach](cosign_attach.md)	 - Provides utilities for attaching artifacts to other artifacts in a registry

