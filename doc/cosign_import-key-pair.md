## cosign import-key-pair

Imports a PEM-encoded RSA or EC private key.

### Synopsis

Imports a PEM-encoded RSA or EC private key for signing.

```
cosign import-key-pair [flags]
```

### Examples

```
  cosign import-key-pair  --key openssl.key --output-key-prefix my-key

  # import PEM-encoded RSA or EC private key and write to import-cosign.key and import-cosign.pub files
  cosign import-key-pair --key <key path>

  # import PEM-encoded RSA or EC private key and write to my-key.key and my-key.pub files
  cosign import-key-pair --key <key path> --output-key-prefix my-key

CAVEATS:
  This command interactively prompts for a password. You can use
  the COSIGN_PASSWORD environment variable to provide one.
```

### Options

```
  -h, --help                       help for import-key-pair
  -k, --key string                 import key pair to use for signing
  -o, --output-key-prefix string   name used for outputted key pairs (default "import-cosign")
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -t, --timeout duration     timeout for commands (default 3m0s)
  -d, --verbose              log debug output
```

### SEE ALSO

* [cosign](cosign.md)	 - A tool for Container Signing, Verification and Storage in an OCI registry.

