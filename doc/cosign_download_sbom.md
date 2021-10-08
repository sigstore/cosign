## cosign download sbom

Download SBOMs from the supplied container image

```
cosign download sbom [flags]
```

### Examples

```
  cosign download sbom <image uri>
```

### Options

```
      --allow-insecure-registry   whether to allow insecure connections to registries. Don't use this for anything but testing
  -h, --help                      help for sbom
      --tag-prefix string         custom prefix to use for tags
      --tag-suffix string         custom suffix to use for tags
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -d, --verbose              log debug output
```

### SEE ALSO

* [cosign download](cosign_download.md)	 - Provides utilities for downloading artifacts and attached artifacts in a registry

