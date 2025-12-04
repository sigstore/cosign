## cosign initialize

Initializes SigStore root to retrieve trusted certificate and key targets for verification.

### Synopsis

Initializes SigStore root to retrieve trusted certificate and key targets for verification.

The following options are used by default:
 - The current trusted Sigstore TUF root is embedded inside cosign at the time of release.
 - SigStore remote TUF repository is pulled from the CDN mirror at tuf-repo-cdn.sigstore.dev.

To provide an out-of-band trusted initial root.json, use the -root flag with a file or URL reference.
This will enable you to point cosign to a separate TUF root.

Any updated TUF repository will be written to $HOME/.sigstore/root/.

Trusted keys and certificate used in cosign verification (e.g. verifying Fulcio issued certificates
with Fulcio root CA) are pulled from the trusted metadata.

```
cosign initialize [flags]
```

### Examples

```
cosign initialize --mirror <url>

# initialize root with distributed root keys, using the default mirror.
cosign initialize

# initialize root with distributed root keys, using the staging mirror.
cosign initialize --staging

# initialize with an out-of-band root key file, using the default mirror.
cosign initialize --root <url>

# initialize with an out-of-band root key file and custom repository mirror.
cosign initialize --mirror <url> --root <url>

# initialize with an out-of-band root key file and custom repository mirror while verifying root checksum.
cosign initialize --mirror <url> --root <url> --root-checksum <sha256>
```

### Options

```
  -h, --help                   help for initialize
      --mirror string          GCS bucket to a SigStore TUF repository, or HTTP(S) base URL, or file:/// for local filestore remote (air-gap) (default "https://tuf-repo-cdn.sigstore.dev")
      --root string            path to trusted initial root. defaults to embedded root
      --root-checksum string   checksum of the initial root, required if root is downloaded via http(s). expects sha256 by default, can be changed to sha512 by providing sha512:<checksum>
      --staging                use the staging TUF repository
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -t, --timeout duration     timeout for commands (default 3m0s)
  -d, --verbose              log debug output
```

### SEE ALSO

* [cosign](cosign.md)	 - A tool for Container Signing, Verification and Storage in an OCI registry.

