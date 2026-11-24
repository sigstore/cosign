## cosign piv-tool set-management-key

sets the management key of a hardware token

```
cosign piv-tool set-management-key [flags]
```

### Options

```
  -h, --help[=true|false]                    help for set-management-key
      --new-key string                       new management key, uses default if empty
      --old-key string                       existing management key, uses default if empty
      --random-management-key[=true|false]   if set to true, generates a new random management key and deletes it after
```

### Options inherited from parent commands

```
  -f, --no-input[=true|false]   skip warnings and confirmations
      --output-file string      log output to a file
  -t, --timeout duration        timeout for commands (default 3m0s)
  -d, --verbose[=true|false]    log debug output
```

### SEE ALSO

* [cosign piv-tool](cosign_piv-tool.md)	 - Provides utilities for managing a hardware token

