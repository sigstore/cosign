## cosign pkcs11-tool list-tokens

List all PKCS11 tokens linked to a module

```
cosign pkcs11-tool list-tokens [flags]
```

### Examples

```
  # list all tokens for a PKCS11 module
  cosign pkcs11-tool list-tokens --module-path /usr/lib/libp11kit.so
```

### Options

```
  -h, --help                 help for list-tokens
      --module-path string   absolute path to the PKCS11 module
```

### Options inherited from parent commands

```
  -f, --no-input             skip warnings and confirmations
      --output-file string   log output to a file
  -t, --timeout duration     timeout for commands (default 3m0s)
  -d, --verbose              log debug output
```

### SEE ALSO

* [cosign pkcs11-tool](cosign_pkcs11-tool.md)	 - Provides utilities for retrieving information from a PKCS11 token.

