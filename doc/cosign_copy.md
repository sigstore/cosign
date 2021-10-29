## cosign copy

Copy the supplied container image and signatures.

```
cosign copy [flags]
```

### Examples

```
  cosign copy <source image> <destination image>

  # copy a container image and its signatures
  cosign copy example.com/src:latest example.com/dest:latest

  # copy the signatures only
  cosign copy --sig-only example.com/src example.com/dest

  # overwrite destination image and signatures
  cosign copy -f example.com/src example.com/dest
```

### Options

```
      --allow-insecure-registry                                                                  whether to allow insecure connections to registries. Don't use this for anything but testing
      --attachment-tag-prefix [AttachmentTagPrefix]sha256-[TargetImageDigest].[AttachmentName]   optional custom prefix to use for attached image tags. Attachment images are tagged as: [AttachmentTagPrefix]sha256-[TargetImageDigest].[AttachmentName]
  -f, --force                                                                                    overwrite destination image(s), if necessary
  -h, --help                                                                                     help for copy
      --k8s-keychain                                                                             whether to use the kubernetes keychain instead of the default keychain (supports workload identity).
      --sig-only                                                                                 only copy the image signature
```

### Options inherited from parent commands

```
      --azure-container-registry-config string   Path to the file containing Azure container registry configuration information.
      --output-file string                       log output to a file
  -d, --verbose                                  log debug output
```

### SEE ALSO

* [cosign](cosign.md)	 - 

