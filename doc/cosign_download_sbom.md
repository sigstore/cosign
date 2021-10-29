## cosign download sbom

Download SBOMs from the supplied container image

```
cosign download sbom [flags]
```

### Examples

```
  cosign download sbom <image uri>
```

### Options

```
      --allow-insecure-registry                                                                  whether to allow insecure connections to registries. Don't use this for anything but testing
      --attachment-tag-prefix [AttachmentTagPrefix]sha256-[TargetImageDigest].[AttachmentName]   optional custom prefix to use for attached image tags. Attachment images are tagged as: [AttachmentTagPrefix]sha256-[TargetImageDigest].[AttachmentName]
  -h, --help                                                                                     help for sbom
      --k8s-keychain                                                                             whether to use the kubernetes keychain instead of the default keychain (supports workload identity).
```

### Options inherited from parent commands

```
      --azure-container-registry-config string   Path to the file containing Azure container registry configuration information.
      --output-file string                       log output to a file
  -d, --verbose                                  log debug output
```

### SEE ALSO

* [cosign download](cosign_download.md)	 - Provides utilities for downloading artifacts and attached artifacts in a registry

