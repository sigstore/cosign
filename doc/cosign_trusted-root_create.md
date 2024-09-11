## cosign trusted-root create

Create a Sigstore protobuf trusted root

### Synopsis

Create a Sigstore protobuf trusted root by supplying verification material

```
cosign trusted-root create [flags]
```

### Options

```
      --ca-intermediates string              path to a file of intermediate CA certificates in PEM format which will be needed when building the certificate chains for the signing certificate. The flag is optional and must be used together with --ca-roots, conflicts with --certificate-chain.
      --ca-roots string                      path to a bundle file of CA certificates in PEM format which will be needed when building the certificate chains for the signing certificate. Conflicts with --certificate-chain.
      --certificate-chain string             path to a list of CA certificates in PEM format which will be needed when building the certificate chain for the signing certificate. Must start with the parent intermediate CA certificate of the signing certificate and end with the root certificate. Conflicts with --ca-roots and --ca-intermediates.
  -h, --help                                 help for create
      --out string                           path to output trusted root
      --rekor-url string                     address of rekor STL server
      --timestamp-certificate-chain string   path to PEM-encoded certificate chain file for the RFC3161 timestamp authority. Must contain the root CA certificate. Optionally may contain intermediate CA certificates
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -t, --timeout duration     timeout for commands (default 3m0s)
  -d, --verbose              log debug output
```

### SEE ALSO

* [cosign trusted-root](cosign_trusted-root.md)	 - Interact with a Sigstore protobuf trusted root

