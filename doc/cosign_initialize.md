## cosign initialize

Initializes SigStore root to retrieve trusted certificate and key targets for verification.

### Synopsis

Initializes SigStore root to retrieve trusted certificate and key targets for verification.

The following options are used by default:
	- The initial 1.root.json is embedded inside cosign.
	- SigStore current TUF repository is pulled from the GCS mirror at sigstore-tuf-root.
	- A default threshold of 3 root signatures is used.

To provide an out-of-band trusted initial root.json, use the -root flag with a file or URL reference.

The resulting updated TUF repository will be written to $HOME/.sigstore/root/.

Trusted keys and certificate used in cosign verification (e.g. verifying Fulcio issued certificates
with Fulcio root CA) are pulled form the trusted metadata.

```
cosign initialize [flags]
```

### Examples

```
  cosign initialize -mirror <url> -out <file>

  # initialize root with distributed root keys, default mirror, and default out path.
  cosign initialize

  # initialize with an out-of-band root key file.
  cosign initialize

  # initialize with an out-of-band root key file and custom repository mirror.
  cosign initialize -mirror <url> -root <url>
```

### Options

```
  -h, --help            help for initialize
      --mirror string   GCS bucket to a SigStore TUF repository. (default "sigstore-tuf-root")
      --root string     path to trusted initial root. defaults to embedded root
      --upload int      threshold of root key signers (default 3)
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -d, --verbose              log debug output
```

### SEE ALSO

* [cosign](cosign.md)	 - 

