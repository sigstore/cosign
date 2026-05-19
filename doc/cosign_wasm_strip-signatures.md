## cosign wasm strip-signatures

Remove embedded wasm-cosign custom sections from a WebAssembly module

```
cosign wasm strip-signatures <module> [flags]
```

### Examples

```
  cosign wasm strip-signatures -o unsigned.wasm signed.wasm

  # read from stdin and write the stripped module to stdout
  cosign wasm strip-signatures -o - < signed.wasm
```

### Options

```
  -h, --help            help for strip-signatures
  -o, --output string   write the unsigned WebAssembly module to FILE
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -t, --timeout duration     timeout for commands (default 3m0s)
  -d, --verbose              log debug output
```

### SEE ALSO

* [cosign wasm](cosign_wasm.md)	 - Utilities for working with WebAssembly modules and embedded wasm-cosign signatures

