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
  cosign copy --only=sig example.com/src example.com/dest

  # copy the signatures, attestations, sbom only
  cosign copy --only=sig,att,sbom example.com/src example.com/dest

  # overwrite destination image and signatures
  cosign copy -f example.com/src example.com/dest

  # copy a container image and its signatures for a specific platform
  cosign copy --platform=linux/amd64 example.com/src:latest example.com/dest:latest
```

### Options

```
      --allow-http-registry                                                                      whether to allow using HTTP protocol while connecting to registries. Don't use this for anything but testing
      --allow-insecure-registry                                                                  whether to allow insecure connections to registries (e.g., with expired or self-signed TLS certificates). Don't use this for anything but testing
      --attachment-tag-prefix [AttachmentTagPrefix]sha256-[TargetImageDigest].[AttachmentName]   optional custom prefix to use for attached image tags. Attachment images are tagged as: [AttachmentTagPrefix]sha256-[TargetImageDigest].[AttachmentName]
  -f, --force                                                                                    overwrite destination image(s), if necessary
  -h, --help                                                                                     help for copy
      --k8s-keychain                                                                             whether to use the kubernetes keychain instead of the default keychain (supports workload identity).
      --only string                                                                              custom string array to only copy specific items, this flag is comma delimited. ex: --only=sbom,sign,att
      --platform string                                                                          only copy container image and its signatures for a specific platform image
      --registry-password string                                                                 registry basic auth password
      --registry-token string                                                                    registry bearer auth token
      --registry-username string                                                                 registry basic auth username
      --sig-only                                                                                 [DEPRECATED] only copy the image signature
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -t, --timeout duration     timeout for commands (default 3m0s)
  -d, --verbose              log debug output
```

### SEE ALSO

* [cosign](cosign.md)	 - A tool for Container Signing, Verification and Storage in an OCI registry.

