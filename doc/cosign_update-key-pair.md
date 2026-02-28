## cosign update-key-pair

Updates the password of a private key.

### Synopsis

Re-encrypts an existing encrypted private key with a new password.

```
cosign update-key-pair [flags]
```

### Examples

```
  cosign update-key-pair --key <key path>

  # update the password of an existing private key
  cosign update-key-pair --key cosign.key

CAVEATS:
  This command interactively prompts for the current password and then the new
  password (twice for confirmation). You can use the COSIGN_PASSWORD environment
  variable to provide the current password and COSIGN_NEW_PASSWORD to provide
  the new password non-interactively.
  Piping passwords is currently not supported.
```

### Options

```
  -h, --help         help for update-key-pair
  -k, --key string   path to the private key file to update the password for
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -t, --timeout duration     timeout for commands (default 3m0s)
  -d, --verbose              log debug output
```

### SEE ALSO

* [cosign](cosign.md)	 - A tool for Container Signing, Verification and Storage in an OCI registry.

