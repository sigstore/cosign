## cosign bundle upgrade

Upgrade a Sigstore protobuf bundle

### Synopsis

Upgrade a Sigstore Protobuf bundle to the latest version. This command only supports standardized bundles.

```
cosign bundle upgrade <bundle> [flags]
```

### Options

```
  -h, --help               help for upgrade
      --out string         path to the output upgraded bundle file
      --rekor-url string   URL of the transparency log (default "https://rekor.sigstore.dev")
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -t, --timeout duration     timeout for commands (default 3m0s)
  -d, --verbose              log debug output
```

### SEE ALSO

* [cosign bundle](cosign_bundle.md)	 - Interact with a Sigstore protobuf bundle

