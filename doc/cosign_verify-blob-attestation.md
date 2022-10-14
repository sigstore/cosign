## cosign verify-blob-attestation

Verify an attestation on the supplied blob

### Synopsis

Verify an attestation on the supplied blob input using the specified key reference.
You may specify either a key or a kms reference to verify against.

The signature may be specified as a path to a file or a base64 encoded string.
The blob may be specified as a path to a file.

```
cosign verify-blob-attestation [flags]
```

### Examples

```
 cosign verify-blob-attestastion (--key <key path>|<key url>|<kms uri>) --signature <sig> [path to BLOB]

  # Verify a simple blob attestation with a DSSE style signature
  cosign verify-blob-attestastion --key cosign.pub (--signature <sig path>|<sig url>)[path to BLOB]


```

### Options

```
  -h, --help               help for verify-blob-attestation
      --key string         path to the public key file, KMS URI or Kubernetes Secret
      --signature string   path to base64-encoded signature over attestation in DSSE format
      --type string        specify a predicate type (slsaprovenance|link|spdx|spdxjson|cyclonedx|vuln|custom) or an URI (default "custom")
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -t, --timeout duration     timeout for commands (default 3m0s)
  -d, --verbose              log debug output
```

### SEE ALSO

* [cosign](cosign.md)	 - A tool for Container Signing, Verification and Storage in an OCI registry.

