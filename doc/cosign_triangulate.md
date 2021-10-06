## cosign triangulate

Outputs the located cosign image reference. This is the location cosign stores the specified artifact type.
cosign triangulate <image uri>

### Synopsis

Outputs the located cosign image reference. This is the location cosign stores the specified artifact type.

```
cosign triangulate [flags]
```

### Options

```
      --allow-insecure-registry   whether to allow insecure connections to registries. Don't use this for anything but testing
  -h, --help                      help for triangulate
      --type string               related attachment to triangulate (attestation|sbom|signature), default signature (default "signature")
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -v, --verbose              log verbose debug output
```

### SEE ALSO

* [cosign](cosign.md)	 - 

