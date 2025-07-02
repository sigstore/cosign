## cosign trusted-root create

Create a Sigstore protobuf trusted root

### Synopsis

Create a Sigstore protobuf trusted root by supplying verification material

```
cosign trusted-root create [flags]
```

### Options

```
      --certificate-chain stringArray             path to a list of CA certificates in PEM format which will be needed when building the certificate chain for the signing certificate. Must start with the parent intermediate CA certificate of the signing certificate and end with the root certificate.
      --ctfe-end-time stringArray                 RFC 3339 string describing validity end time for key use by certificate transparency log.
      --ctfe-key stringArray                      path to a PEM-encoded public key used by certificate authority for certificate transparency log.
      --ctfe-start-time stringArray               RFC 3339 string describing validity start time for key use by certificate transparency log.
      --ctfe-url stringArray                      URL of the certificate transparency log.
      --fulcio-uri stringArray                    URI of the Fulcio server issuing certificates.
  -h, --help                                      help for create
      --out string                                path to output trusted root
      --rekor-end-time stringArray                RFC 3339 string describing validity end time for key use by transparency log like Rekor.
      --rekor-key stringArray                     path to a PEM-encoded public key used by transparency log like Rekor. For Rekor V2, append the Rekor server name with ',', e.g. '--rekor-key=/path/to/key.pub,rekor.example.test'.
      --rekor-start-time stringArray              RFC 3339 string describing validity start time for key use by transparency log like Rekor.
      --rekor-url stringArray                     URL of the transparency log.
      --timestamp-certificate-chain stringArray   path to PEM-encoded certificate chain file for the RFC3161 timestamp authority. Must contain the root CA certificate. Optionally may contain intermediate CA certificates
      --timestamp-uri stringArray                 URI of the timestamp authority server.
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -t, --timeout duration     timeout for commands (default 3m0s)
  -d, --verbose              log debug output
```

### SEE ALSO

* [cosign trusted-root](cosign_trusted-root.md)	 - Interact with a Sigstore protobuf trusted root

