## cosign login

Log in to a registry

```
cosign login [OPTIONS] [SERVER] [flags]
```

### Examples

```
  # Log in to reg.example.com
  cosign login reg.example.com -u AzureDiamond -p hunter2
```

### Options

```
  -h, --help              help for login
  -p, --password string   Password
      --password-stdin    Take the password from stdin
  -u, --username string   Username
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -t, --timeout duration     timeout for commands (default 3m0s)
  -d, --verbose              log debug output
```

### SEE ALSO

* [cosign](cosign.md)	 - A tool for Container Signing, Verification and Storage in an OCI registry.

