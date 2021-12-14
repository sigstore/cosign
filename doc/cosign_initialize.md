## cosign initialize

Initializes SigStore root to retrieve trusted certificate and key targets for verification.

### Synopsis

Initializes SigStore root to retrieve trusted certificate and key targets for verification.

The following options are used by default:
 - The current trusted Sigstore TUF root is embedded inside cosign at the time of release.
 - SigStore remote TUF repository is pulled from the GCS mirror at sigstore-tuf-root.

To provide an out-of-band trusted initial root.json, use the -root flag with a file or URL reference.
This will enable you to point cosign to a separate TUF root.

Any updated TUF repository will be written to $HOME/.sigstore/root/.

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

# initialize with an out-of-band root key file, using the default mirror.
cosign initialize -root <url>

# initialize with an out-of-band root key file and custom repository mirror.
cosign initialize -mirror <url> -root <url>
```

### Options

```
  -h, --help            help for initialize
      --mirror string   GCS bucket to a SigStore TUF repository or HTTP(S) base URL (default "sigstore-tuf-root")
      --root string     path to trusted initial root. defaults to embedded root
```

### Options inherited from parent commands

```
      --azure-container-registry-config string   Path to the file containing Azure container registry configuration information.
      --output-file string                       log output to a file
  -d, --verbose                                  log debug output
```

### SEE ALSO

* [cosign](cosign.md)	 - 

