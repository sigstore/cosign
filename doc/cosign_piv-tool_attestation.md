## cosign piv-tool attestation

attestation contains commands to manage a hardware token

```
cosign piv-tool attestation [flags]
```

### Options

```
  -h, --help            help for attestation
  -o, --output string   format to output attestation information in. (text|json) (default "text")
      --slot string     Slot to use for generated key (authentication|signature|card-authentication|key-management)
```

### Options inherited from parent commands

```
  -f, --no-input             skip warnings and confirmations
      --output-file string   log output to a file
  -d, --verbose              log debug output
```

### SEE ALSO

* [cosign piv-tool](cosign_piv-tool.md)	 - Provides utilities for managing a hardware token

