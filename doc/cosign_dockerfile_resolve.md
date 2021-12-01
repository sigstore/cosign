## cosign dockerfile resolve

Resolve the digest of the images and rewrites them with fully qualified image reference

```
cosign dockerfile resolve [flags]
```

### Examples

```
  cosign dockerfile resolve Dockerfile
		
		# specify output file
		cosign dockerfile resolve -o Dockerfile.edited Dockerfile

```

### Options

```
  -h, --help            help for resolve
  -o, --output string   output an updated Dockerfile to file
```

### Options inherited from parent commands

```
      --azure-container-registry-config string   Path to the file containing Azure container registry configuration information.
      --output-file string                       log output to a file
  -d, --verbose                                  log debug output
```

### SEE ALSO

* [cosign dockerfile](cosign_dockerfile.md)	 - Provides utilities for discovering images in and performing operations on Dockerfiles

