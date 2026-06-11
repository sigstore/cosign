## cosign piv-tool set-pin

Set the PIN on a hardware token

```
cosign piv-tool set-pin [flags]
```

### Examples

```
  # set a new PIN interactively (uses defaults if flags omitted)
  cosign piv-tool set-pin

  # set a specific PIN
  cosign piv-tool set-pin --old-pin <old-pin> --new-pin <new-pin>
```

### Options

```
  -h, --help             help for set-pin
      --new-pin string   new PIN, uses default if empty
      --old-pin string   existing PIN, uses default if empty
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

