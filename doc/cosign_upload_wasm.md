## cosign upload wasm

Upload a wasm module to the supplied container image reference

```
cosign upload wasm [flags]
```

### Examples

```
  cosign upload wasm -f foo.wasm <image uri>
```

### Options

```
      --allow-insecure-registry   whether to allow insecure connections to registries. Don't use this for anything but testing
  -f, --file string               path to the wasm file to upload
  -h, --help                      help for wasm
      --tag-prefix string         custom prefix to use for tags
      --tag-suffix string         custom suffix to use for tags
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -d, --verbose              log debug output
```

### SEE ALSO

* [cosign upload](cosign_upload.md)	 - Provides utilities for uploading artifacts to a registry

