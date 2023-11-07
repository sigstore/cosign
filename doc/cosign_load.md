## cosign load

Load a signed image on disk to a remote registry

### Synopsis

Load a signed image on disk to a remote registry

```
cosign load [flags]
```

### Examples

```
  cosign load --dir <path to directory> <IMAGE>
```

### Options

```
      --allow-http-registry                                                                      whether to allow using HTTP protocol while connecting to registries. Don't use this for anything but testing
      --allow-insecure-registry                                                                  whether to allow insecure connections to registries (e.g., with expired or self-signed TLS certificates). Don't use this for anything but testing
      --attachment-tag-prefix [AttachmentTagPrefix]sha256-[TargetImageDigest].[AttachmentName]   optional custom prefix to use for attached image tags. Attachment images are tagged as: [AttachmentTagPrefix]sha256-[TargetImageDigest].[AttachmentName]
      --dir string                                                                               path to directory where the signed image is stored on disk
  -h, --help                                                                                     help for load
      --k8s-keychain                                                                             whether to use the kubernetes keychain instead of the default keychain (supports workload identity).
      --registry-password string                                                                 registry basic auth password
      --registry-token string                                                                    registry bearer auth token
      --registry-username string                                                                 registry basic auth username
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -t, --timeout duration     timeout for commands (default 3m0s)
  -d, --verbose              log debug output
```

### SEE ALSO

* [cosign](cosign.md)	 - A tool for Container Signing, Verification and Storage in an OCI registry.

