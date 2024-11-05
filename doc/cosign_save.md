## cosign save

Save the container image and associated signatures to disk at the specified directory.

### Synopsis

Save the container image and associated signatures to disk at the specified directory.

```
cosign save [flags]
```

### Examples

```
  cosign save --dir <path to directory> <IMAGE>
```

### Options

```
      --allow-http-registry                                                                      whether to allow using HTTP protocol while connecting to registries. Don't use this for anything but testing
      --allow-insecure-registry                                                                  whether to allow insecure connections to registries (e.g., with expired or self-signed TLS certificates). Don't use this for anything but testing
      --attachment-tag-prefix [AttachmentTagPrefix]sha256-[TargetImageDigest].[AttachmentName]   optional custom prefix to use for attached image tags. Attachment images are tagged as: [AttachmentTagPrefix]sha256-[TargetImageDigest].[AttachmentName]
      --dir string                                                                               path to dir where the signed image should be stored on disk
  -h, --help                                                                                     help for save
      --k8s-keychain                                                                             whether to use the kubernetes keychain instead of the default keychain (supports workload identity).
      --registry-cacert string                                                                   path to the X.509 CA certificate file in PEM format to be used for the connection to the registry
      --registry-client-cert string                                                              path to the X.509 certificate file in PEM format to be used for the connection to the registry
      --registry-client-key string                                                               path to the X.509 private key file in PEM format to be used, together with the 'registry-client-cert' value, for the connection to the registry
      --registry-password string                                                                 registry basic auth password
      --registry-server-name string                                                              SAN name to use as the 'ServerName' tls.Config field to verify the mTLS connection to the registry
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

