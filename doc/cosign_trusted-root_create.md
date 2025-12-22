## cosign trusted-root create

Create a Sigstore protobuf trusted root

### Synopsis

Create a Sigstore protobuf trusted root by supplying verification material.

Each service is specified via a repeatable flag (--fulcio, --rekor, --ctfe, --tsa) that takes a comma-separated list of key-value pairs.

```
cosign trusted-root create [flags]
```

### Examples

```
cosign trusted-root create \
    --fulcio="url=https://fulcio.sigstore.dev,certificate-chain=/path/to/fulcio.pem,end-time=2025-01-01T00:00:00Z" \
    --rekor="url=https://rekor.sigstore.dev,public-key=/path/to/rekor.pub,start-time=2024-01-01T00:00:00Z" \
    --ctfe="url=https://ctfe.sigstore.dev,public-key=/path/to/ctfe.pub,start-time=2024-01-01T00:00:00Z" \
    --tsa="url=https://timestamp.sigstore.dev/api/v1/timestamp,certificate-chain=/path/to/tsa.pem" \
    --out trusted-root.json
```

### Options

```
      --ctfe stringArray        ctfe service specification, as a comma-separated key-value list.
                                Required keys: url, public-key (path to PEM-encoded public key), start-time. Optional keys: end-time.
      --fulcio stringArray      fulcio service specification, as a comma-separated key-value list.
                                Required keys: url, certificate-chain (path to PEM-encoded certificate chain). Optional keys: start-time, end-time.
  -h, --help                    help for create
      --no-default-ctfe         removes the default CTFE URLs from the trusted root.
      --no-default-fulcio       removes the default Fulcio URLs from the trusted root.
      --no-default-rekor        removes the default Rekor URLs from the trusted root.
      --no-default-tsa          removes the default TSA URLs from the trusted root.
      --out string              path to output trusted root
      --rekor stringArray       rekor service specification, as a comma-separated key-value list.
                                Required keys: url, public-key (path to PEM-encoded public key), start-time. Optional keys: end-time, origin.
      --tsa stringArray         timestamping authority specification, as a comma-separated key-value list.
                                Required keys: url, certificate-chain (path to PEM-encoded certificate chain). Optional keys: start-time, end-time.
      --with-default-services   use the Sigstore TUF root as default values to populate the trusted root. Specifying the other service flags will override the default values.
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -t, --timeout duration     timeout for commands (default 3m0s)
  -d, --verbose              log debug output
```

### SEE ALSO

* [cosign trusted-root](cosign_trusted-root.md)	 - Interact with a Sigstore protobuf trusted root

