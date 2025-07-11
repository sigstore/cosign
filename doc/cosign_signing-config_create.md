## cosign signing-config create

Create a Sigstore protobuf signing config

### Synopsis

Create a Sigstore protobuf signing config by supplying verification material for Fulcio, Rekor, OIDC, and TSA services.
Each service is specified via a repeatable flag (--fulcio, --rekor, --oidc-provider, --tsa) that takes a comma-separated list of key-value pairs.

```
cosign signing-config create [flags]
```

### Examples

```
cosign signing-config create \
    --fulcio="url=https://fulcio.sigstore.dev,api-version=1,start-time=2024-01-01T00:00:00Z,end-time=2025-01-01T00:00:00Z,operator=sigstore.dev" \
    --rekor="url=https://rekor.sigstore.dev,api-version=1,start-time=2024-01-01T00:00:00Z,operator=sigstore.dev" \
    --rekor-config="ANY" \
    --oidc-provider="url=https://oauth2.sigstore.dev/auth,api-version=1,start-time=2024-01-01T00:00:00Z,operator=sigstore.dev" \
    --tsa="url=https://timestamp.sigstore.dev/api/v1/timestamp,api-version=1,start-time=2024-01-01T00:00:00Z,operator=sigstore.dev" \
    --tsa-config="EXACT:1" \
    --out signing-config.json
```

### Options

```
      --fulcio stringArray          fulcio service specification, as a comma-separated key-value list.
                                    Required keys: url, api-version (integer), start-time, operator. Optional keys: end-time.
  -h, --help                        help for create
      --oidc-provider stringArray   oidc provider specification, as a comma-separated key-value list.
                                    Required keys: url, api-version (integer), start-time, operator. Optional keys: end-time.
      --out string                  path to output signing config
      --rekor stringArray           rekor service specification, as a comma-separated key-value list.
                                    Required keys: url, api-version (integer), start-time, operator. Optional keys: end-time.
      --rekor-config string         rekor configuration. Required if --rekor is provided. One of: ANY, ALL, EXACT:<count>
      --tsa stringArray             timestamping authority specification, as a comma-separated key-value list.
                                    Required keys: url, api-version (integer), start-time, operator. Optional keys: end-time.
      --tsa-config string           timestamping authority configuration. Required if --tsa is provided. One of: ANY, ALL, EXACT:<count>
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -t, --timeout duration     timeout for commands (default 3m0s)
  -d, --verbose              log debug output
```

### SEE ALSO

* [cosign signing-config](cosign_signing-config.md)	 - Interact with a Sigstore protobuf signing config

