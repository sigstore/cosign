## cosign bundle create

Create a Sigstore protobuf bundle

### Synopsis

Create a Sigstore protobuf bundle by supplying signed material

```
cosign bundle create [flags]
```

### Options

```
      --artifact string            path to artifact FILE
      --attestation string         path to attestation FILE
      --bundle string              path to old format bundle FILE
      --certificate string         path to the signing certificate, likely from Fulco.
  -h, --help                       help for create
      --ignore-tlog                ignore transparency log verification, to be used when an artifact signature has not been uploaded to the transparency log.
      --key string                 path to the public key file, KMS URI or Kubernetes Secret
      --out string                 path to output bundle
      --rekor-url string           address of rekor STL server (default "https://rekor.sigstore.dev")
      --rfc3161-timestamp string   path to RFC3161 timestamp FILE
      --signature string           path to base64-encoded signature over attestation in DSSE format
      --sk                         whether to use a hardware security key
      --slot string                security key slot to use for generated key (authentication|signature|card-authentication|key-management) (default "signature")
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -t, --timeout duration     timeout for commands (default 3m0s)
  -d, --verbose              log debug output
```

### SEE ALSO

* [cosign bundle](cosign_bundle.md)	 - Interact with a Sigstore protobuf bundle

