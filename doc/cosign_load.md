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
      --azure-container-registry-config string   Path to the file containing Azure container registry configuration information.
      --output-file string                       log output to a file
  -d, --verbose                                  log debug output
```

### SEE ALSO

* [cosign](cosign.md)	 - 

