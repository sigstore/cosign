## cosign wasm sign

Sign a WebAssembly module with an embedded wasm-cosign custom section

```
cosign wasm sign <module> [flags]
```

### Examples

```
  cosign wasm sign --wasm-output signed.wasm --key cosign.key module.wasm

  # append another wasm-cosign custom section to an already signed module
  cosign wasm sign --wasm-output resigned.wasm --key cosign.key module.wasm
```

### Options

```
      --bundle string                    write everything required to verify the blob to a FILE
      --certificate string               path to the X.509 certificate for signing attestation
      --certificate-chain string         path to a list of CA X.509 certificates in PEM format which will be needed when building the certificate chain for the signed attestation. Must start with the parent intermediate CA certificate of the signing certificate and end with the root certificate.
      --fulcio-auth-flow string          fulcio interactive oauth2 flow to use for certificate from fulcio. Defaults to determining the flow based on the runtime environment. (options) normal|device|token|client_credentials
  -h, --help                             help for sign
      --identity-token string            identity token to use for certificate from fulcio. the token or a path to a file containing the token is accepted.
      --key string                       path to the private key file, KMS URI or Kubernetes Secret
      --oidc-client-id string            OIDC client ID for application (default "sigstore")
      --oidc-client-secret-file string   Path to file containing OIDC client secret for application
      --oidc-disable-ambient-providers   Disable ambient OIDC providers. When true, ambient credentials will not be read
      --oidc-provider string             Specify the provider to get the OIDC token from (Optional). If unset, all options will be tried. Options include: [spiffe, google, github-actions, filesystem, buildkite-agent]
      --oidc-redirect-url string         OIDC redirect URL (Optional). The default oidc-redirect-url is 'http://localhost:0/auth/callback'.
      --signing-algorithm string         signing algorithm to use for signing/hashing (allowed ecdsa-sha2-256-nistp256, ecdsa-sha2-384-nistp384, ecdsa-sha2-512-nistp521, rsa-sign-pkcs1-2048-sha256, rsa-sign-pkcs1-3072-sha256, rsa-sign-pkcs1-4096-sha256) (default "ecdsa-sha2-256-nistp256")
      --signing-config string            path to a signing config file. Must provide --bundle or --wasm-output, which will output verification material in the new format
      --sk                               whether to use a hardware security key
      --slot string                      security key slot to use for generated key (default: signature) (authentication|signature|card-authentication|key-management)
      --timestamp-client-cacert string   path to the X.509 CA certificate file in PEM format to be used for the connection to the TSA Server
      --timestamp-client-cert string     path to the X.509 certificate file in PEM format to be used for the connection to the TSA Server
      --timestamp-client-key string      path to the X.509 private key file in PEM format to be used, together with the 'timestamp-client-cert' value, for the connection to the TSA Server
      --timestamp-server-name string     SAN name to use as the 'ServerName' tls.Config field to verify the mTLS connection to the TSA Server
      --trusted-root string              optional path to a TrustedRoot JSON file to verify a signature after signing
      --use-signing-config               whether to use a TUF-provided signing config for the service URLs. Must provide --bundle or --wasm-output, which will output verification material in the new format (default true)
      --wasm-output string               write a signed WebAssembly module to FILE with the Sigstore bundle appended in a wasm-cosign custom section
  -y, --yes                              skip confirmation prompts for non-destructive operations
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -t, --timeout duration     timeout for commands (default 3m0s)
  -d, --verbose              log debug output
```

### SEE ALSO

* [cosign wasm](cosign_wasm.md)	 - Utilities for working with WebAssembly modules and embedded wasm-cosign signatures

