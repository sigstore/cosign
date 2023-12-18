## cosign version

Prints the version

```
cosign version [flags]
```

### Options

```
  -h, --help   help for version
      --json   print JSON instead of text
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -t, --timeout duration     timeout for commands (default 3m0s)
  -d, --verbose              log debug output
```

## Expected Behaviour
From version 2.1.0 (as part of a [dependency update](https://github.com/sigstore/cosign/commit/40dbbd8b09bd5c30191d6e7e7ced3bbd7f6ea559)), the version metadata is [printed to standard output](https://github.com/kubernetes-sigs/release-utils/pull/76). By default it includes the package version, commit hash, git tree state, build date, Go version, compiler toolchain and current platform.

### SEE ALSO

* [cosign](cosign.md)	 - A tool for Container Signing, Verification and Storage in an OCI registry.

