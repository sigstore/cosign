## cosign dockerfile resolve

Resolve the digest of the images and rewrites them with fully qualified image reference

### Synopsis

Resolve the digest of the images and rewrites them with fully qualified image reference

This command creates a surface which resolves mutable image tags into immutable image digests:
	- FROM <tag>, it rewrites the Dockerfile to FROM <digest>

Using FROM without <digest> is dangerous because even if what's currently tagged on the registry is signed properly,
there is a race before the FROM is evaluated (what if it changes!), or (with docker build) it's possible that
what is in the local cache(!) is what's actually used, and not what was verified! (See issue #648)

This command does NOT do image verification; instead it only rewrites all image tags to corresponding digest(s).

The following image reference definitions are currently supported:
	-	FROM --platform=linux/amd64 gcr.io/distroless/base AS base
	-	COPY --from=gcr.io/distroless/base

```
cosign dockerfile resolve [flags]
```

### Examples

```
  cosign dockerfile resolve Dockerfile
		
		# print to stdout
		cosign dockerfile resolve Dockerfile

		# specify a output file
		cosign dockerfile resolve -o Dockerfile.resolved Dockerfile
```

### Options

```
  -h, --help            help for resolve
  -o, --output string   output an updated Dockerfile to file
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -t, --timeout duration     timeout for commands (default 3m0s)
  -d, --verbose              log debug output
```

### SEE ALSO

* [cosign dockerfile](cosign_dockerfile.md)	 - Provides utilities for discovering images in and performing operations on Dockerfiles

