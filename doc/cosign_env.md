## cosign env

Prints Cosign environment variables

```
cosign env [flags]
```

### Examples

```
  cosign env

  # show environment variables with descriptions
  cosign env --show-descriptions

  # show environment variables including sensitive values
  cosign env --show-descriptions --show-sensitive-values
```

### Options

```
  -h, --help[=true|false]                    help for env
      --show-descriptions[=true|false]       show descriptions for environment variables (default true)
      --show-sensitive-values[=true|false]   show values of sensitive environment variables
```

### Options inherited from parent commands

```
      --output-file string     log output to a file
  -t, --timeout duration       timeout for commands (default 3m0s)
  -d, --verbose[=true|false]   log debug output
```

### SEE ALSO

* [cosign](cosign.md)	 - A tool for Container Signing, Verification and Storage in an OCI registry

