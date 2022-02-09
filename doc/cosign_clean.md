## cosign clean

Remove all signatures from an image.

```
cosign clean [flags]
```

### Examples

```
  cosign clean <IMAGE>
```

### Options

```
      --allow-insecure-registry                                                                  whether to allow insecure connections to registries. Don't use this for anything but testing
      --attachment-tag-prefix [AttachmentTagPrefix]sha256-[TargetImageDigest].[AttachmentName]   optional custom prefix to use for attached image tags. Attachment images are tagged as: [AttachmentTagPrefix]sha256-[TargetImageDigest].[AttachmentName]
  -h, --help                                                                                     help for clean
      --k8s-keychain                                                                             whether to use the kubernetes keychain instead of the default keychain (supports workload identity).
      --type string                                                                              a type of clean: <signature|attestation|sbom|all> (default: all) (default "all")
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -t, --timeout duration     timeout for commands (default 3m0s)
  -d, --verbose              log debug output
```

### SEE ALSO

* [cosign](cosign.md)	 - 

