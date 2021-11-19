## cosign import-key-pair

Imports a PEM-encoded RSA or EC private key.

### Synopsis

Imports a PEM-encoded RSA or EC private key for signing.

```
cosign import-key-pair [flags]
```

### Examples

```
  cosign import-key-pair  --key openssl.key

  # import PEM-encoded RSA or EC private key and write to import-cosign.key and import-cosign.pub files
  cosign import-key-pair --key <key path>

CAVEATS:
  This command interactively prompts for a password. You can use
  the COSIGN_PASSWORD environment variable to provide one.
```

### Options

```
  -h, --help         help for import-key-pair
      --key string   import key pair to use for signing
```

### Options inherited from parent commands

```
      --azure-container-registry-config string   Path to the file containing Azure container registry configuration information.
      --output-file string                       log output to a file
  -d, --verbose                                  log debug output
```

### SEE ALSO

* [cosign](cosign.md)	 - 

