## cosign wasm list-signatures

List embedded wasm-cosign signatures in a WebAssembly module

```
cosign wasm list-signatures <module> [flags]
```

### Examples

```
  cosign wasm list-signatures module.wasm

  # emit machine-readable signature metadata
  cosign wasm list-signatures -o json module.wasm
```

### Options

```
  -h, --help            help for list-signatures
  -o, --output string   output format for embedded signatures (json|text) (default "text")
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -t, --timeout duration     timeout for commands (default 3m0s)
  -d, --verbose              log debug output
```

### SEE ALSO

* [cosign wasm](cosign_wasm.md)	 - Utilities for working with WebAssembly modules and embedded wasm-cosign signatures

