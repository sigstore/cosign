## cosign attach signature

Attach signatures to the supplied container image

```
cosign attach signature [flags]
```

### Examples

```
  cosign attach signature <image uri>
```

### Options

```
      --allow-insecure-registry   whether to allow insecure connections to registries. Don't use this for anything but testing
  -h, --help                      help for signature
      --payload string            path to the payload covered by the signature (if using another format)
      --signature string          the signature, path to the signature, or {-} for stdin
      --tag-prefix string         custom prefix to use for tags
      --tag-suffix string         custom suffix to use for tags
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -d, --verbose              log debug output
```

### SEE ALSO

* [cosign attach](cosign_attach.md)	 - Provides utilities for attaching artifacts to other artifacts in a registry

