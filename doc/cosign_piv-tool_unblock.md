## cosign piv-tool unblock

Unblock a hardware token and set a new PIN

```
cosign piv-tool unblock [flags]
```

### Examples

```
  # unblock the token using the PUK and set a new PIN
  cosign piv-tool unblock --puk <puk> --new-PIN <new-pin>
```

### Options

```
  -h, --help             help for unblock
      --new-PIN string   new PIN, uses default if empty
      --puk string       existing PUK, uses default if empty
```

### Options inherited from parent commands

```
  -f, --no-input             skip warnings and confirmations
      --output-file string   log output to a file
  -t, --timeout duration     timeout for commands (default 3m0s)
  -d, --verbose              log debug output
```

### SEE ALSO

* [cosign piv-tool](cosign_piv-tool.md)	 - Provides utilities for managing a hardware token

