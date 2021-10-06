## cosign upload blob

Upload one or more blobs to the supplied container image address.

```
cosign upload blob [flags]
```

### Examples

```
  cosign upload blob -f <blob ref> <image uri>

  # upload a blob named foo to the location specified by <IMAGE>
  cosign upload blob -f foo <IMAGE>

  # upload a blob named foo to the location specified by <IMAGE>, setting the os field to "MYOS".
  cosign upload blob -f foo:MYOS <IMAGE>

  # upload a blob named foo to the location specified by <IMAGE>, setting the os field to "MYOS" and the platform field to "MYPLATFORM".
  cosign upload blob -f foo:MYOS/MYPLATFORM <IMAGE>

  # upload two blobs named foo-darwin and foo-linux to the location specified by <IMAGE>, setting the os fields
  cosign upload blob -f foo-darwin:darwin -f foo-linux:linux <IMAGE>
```

### Options

```
      --allow-insecure-registry   whether to allow insecure connections to registries. Don't use this for anything but testing
      --ct string                 content type to set
  -f, --files strings             <filepath>:[platform/arch]
  -h, --help                      help for blob
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -v, --verbose              log verbose debug output
```

### SEE ALSO

* [cosign upload](cosign_upload.md)	 - Provides utilities for uploading artifacts to a registry

