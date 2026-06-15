## cosign piv-tool generate-key

Generate a new signing key on the hardware token

```
cosign piv-tool generate-key [flags]
```

### Examples

```
  # generate a key with default settings (slot 9c, always-touch policy)
  cosign piv-tool generate-key

  # generate a key in a specific slot with custom PIN and touch policies
  cosign piv-tool generate-key --slot 9c --pin-policy once --touch-policy always
```

### Options

```
  -h, --help                    help for generate-key
      --management-key string   management key, uses default if empty
      --pin-policy string       PIN policy for slot (never|once|always)
      --random-management-key   if set to true, generates a new random management key and deletes it after
      --slot string             Slot to use for generated key (authentication|signature|card-authentication|key-management)
      --touch-policy string     Touch policy for slot (never|always|cached)
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

