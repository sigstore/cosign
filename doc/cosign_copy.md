## cosign copy

Copy the supplied container image and signatures.

```
cosign copy [flags]
```

### Examples

```
  cosign copy <source image> <destination image>

  # copy a container image and its signatures
  cosign copy example.com/src:latest example.com/dest:latest

  # copy the signatures only
  cosign copy --sig-only example.com/src example.com/dest

  # overwrite destination image and signatures
  cosign copy -f example.com/src example.com/dest
```

### Options

```
      --allow-insecure-registry   whether to allow insecure connections to registries. Don't use this for anything but testing
  -f, --force                     overwrite destination image(s), if necessary
  -h, --help                      help for copy
      --sig-only                  only copy the image signature
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -v, --verbose              log verbose debug output
```

### SEE ALSO

* [cosign](cosign.md)	 - 

