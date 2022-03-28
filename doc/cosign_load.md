## cosign load

Load a signed image on disk to a remote registry

### Synopsis

Load a signed image on disk to a remote registry

```
cosign load [flags]
```

### Examples

```
  cosign load --dir <path to directory> <IMAGE>
```

### Options

```
      --dir string   path to directory where the signed image is stored on disk
  -h, --help         help for load
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -t, --timeout duration     timeout for commands (default 3m0s)
  -d, --verbose              log debug output
```

### SEE ALSO

* [cosign](cosign.md)	 - A tool for Container Signing, Verification and Storage in an OCI registry.

