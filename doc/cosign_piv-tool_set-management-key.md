## cosign piv-tool set-management-key

Set the management key of a hardware token

```
cosign piv-tool set-management-key [flags]
```

### Examples

```
  # set a new management key interactively (uses defaults if flags omitted)
  cosign piv-tool set-management-key

  # set a random management key
  cosign piv-tool set-management-key --random-management-key

  # set a specific new management key
  cosign piv-tool set-management-key --old-key <old-key> --new-key <new-key>
```

### Options

```
  -h, --help                    help for set-management-key
      --new-key string          new management key, uses default if empty
      --old-key string          existing management key, uses default if empty
      --random-management-key   if set to true, generates a new random management key and deletes it after
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

