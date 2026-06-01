## cosign-lite initialize

Initialize TUF roots of trust

```
cosign-lite initialize [flags]
```

### Options

```
  -h, --help                   help for initialize
      --mirror string          GCS bucket to a SigStore TUF repository, or HTTP(S) base URL, or file:/// for local filestore remote (air-gap) (default "https://tuf-repo-cdn.sigstore.dev")
      --root string            path to trusted initial root. defaults to embedded root
      --root-checksum string   checksum of the initial root, required if root is downloaded via http(s). expects sha256 by default, can be changed to sha512 by providing sha512:<checksum>
      --staging                use the staging TUF repository
```

### SEE ALSO

* [cosign-lite](cosign-lite.md)	 - cosign-lite is a lightweight Sigstore signing and verification utility

