## cosign bundle create-from-container

Create Sigstore protobuf bundles from legacy container attestations

### Synopsis

Create Sigstore protobuf bundles from attestations stored in the
legacy tag-based format (.att / .sig) for a container image, and attach them to
the image as OCI 1.1 referrers. Bundles that are already attached are skipped.

```
cosign bundle create-from-container IMAGE [flags]
```

### Examples

```
  # convert keyless attestations
	cosign bundle create-from-container <IMAGE>

  # convert attestations created with a key
			cosign bundle create-from-container --key cosign.pub <IMAGE>
```

### Options

```
      --allow-http-registry           whether to allow using HTTP protocol while connecting to registries. Don't use this for anything but testing
      --allow-insecure-registry       whether to allow insecure connections to registries (e.g., with expired or self-signed TLS certificates). Don't use this for anything but testing
  -h, --help                          help for create-from-container
      --ignore-tlog                   ignore transparency log verification, to be used when an artifact signature has not been uploaded to the transparency log.
      --k8s-keychain                  whether to use the kubernetes keychain instead of the default keychain (supports workload identity).
      --key string                    path to the public key file, KMS URI or Kubernetes Secret
      --registry-cacert string        path to the X.509 CA certificate file in PEM format to be used for the connection to the registry
      --registry-client-cert string   path to the X.509 certificate file in PEM format to be used for the connection to the registry
      --registry-client-key string    path to the X.509 private key file in PEM format to be used, together with the 'registry-client-cert' value, for the connection to the registry
      --registry-password string      registry basic auth password
      --registry-server-name string   SAN name to use as the 'ServerName' tls.Config field to verify the mTLS connection to the registry
      --registry-token string         registry bearer auth token
      --registry-username string      registry basic auth username
      --rekor-url string              address of rekor STL server (default "https://rekor.sigstore.dev")
      --sk                            whether to use a hardware security key
      --slot string                   security key slot to use for generated key (authentication|signature|card-authentication|key-management) (default "signature")
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -t, --timeout duration     timeout for commands (default 3m0s)
  -d, --verbose              log debug output
```

### SEE ALSO

* [cosign bundle](cosign_bundle.md)	 - Interact with a Sigstore protobuf bundle

