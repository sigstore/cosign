## cosign sign-blob

Sign the supplied blob, outputting the base64-encoded signature to stdout.

```
cosign sign-blob [flags]
```

### Examples

```
  cosign sign-blob --key <key path>|<kms uri> <blob>

  # sign a blob with Google sign-in (experimental)
  cosign sign-blob <FILE> --output-signature <FILE> --output-certificate <FILE>

  # sign a blob with a local key pair file
  cosign sign-blob --key cosign.key <FILE>

  # sign a blob with a key stored in an environment variable
  cosign sign-blob --key env://[ENV_VAR] <FILE>

  # sign a blob with a key pair stored in Azure Key Vault
  cosign sign-blob --key azurekms://[VAULT_NAME][VAULT_URI]/[KEY] <FILE>

  # sign a blob with a key pair stored in AWS KMS
  cosign sign-blob --key awskms://[ENDPOINT]/[ID/ALIAS/ARN] <FILE>

  # sign a blob with a key pair stored in Google Cloud KMS
  cosign sign-blob --key gcpkms://projects/[PROJECT]/locations/global/keyRings/[KEYRING]/cryptoKeys/[KEY] <FILE>

  # sign a blob with a key pair stored in Hashicorp Vault
  cosign sign-blob --key hashivault://[KEY] <FILE>
```

### Options

```
      --b64                              whether to base64 encode the output (default true)
      --bundle string                    write everything required to verify the blob to a FILE
      --certificate string               path to the X.509 certificate for signing attestation
      --certificate-chain string         path to a list of CA X.509 certificates in PEM format which will be needed when building the certificate chain for the signed attestation. Must start with the parent intermediate CA certificate of the signing certificate and end with the root certificate.
      --fulcio-auth-flow string          fulcio interactive oauth2 flow to use for certificate from fulcio. Defaults to determining the flow based on the runtime environment. (options) normal|device|token|client_credentials
      --fulcio-url string                address of sigstore PKI server (default "https://fulcio.sigstore.dev")
  -h, --help                             help for sign-blob
      --identity-token string            identity token to use for certificate from fulcio. the token or a path to a file containing the token is accepted.
      --insecure-skip-verify             skip verifying fulcio published to the SCT (this should only be used for testing).
      --issue-certificate                issue a code signing certificate from Fulcio, even if a key is provided
      --key string                       path to the private key file, KMS URI or Kubernetes Secret
      --new-bundle-format                output bundle in new format that contains all verification material (default true)
      --oidc-client-id string            OIDC client ID for application (default "sigstore")
      --oidc-client-secret-file string   Path to file containing OIDC client secret for application
      --oidc-disable-ambient-providers   Disable ambient OIDC providers. When true, ambient credentials will not be read
      --oidc-issuer string               OIDC provider to be used to issue ID token (default "https://oauth2.sigstore.dev/auth")
      --oidc-provider string             Specify the provider to get the OIDC token from (Optional). If unset, all options will be tried. Options include: [spiffe, google, github-actions, filesystem, buildkite-agent]
      --oidc-redirect-url string         OIDC redirect URL (Optional). The default oidc-redirect-url is 'http://localhost:0/auth/callback'.
      --output string                    write the signature to FILE
      --output-certificate string        write the certificate to FILE
      --output-signature string          write the signature to FILE
      --rekor-url string                 address of rekor STL server (default "https://rekor.sigstore.dev")
      --rekor-version uint32             version of rekor API (default 1)
      --rfc3161-timestamp string         write the RFC3161 timestamp to a file
      --signing-algorithm string         signing algorithm to use for signing/hashing (allowed ecdsa-sha2-256-nistp256, ecdsa-sha2-384-nistp384, ecdsa-sha2-512-nistp521, rsa-sign-pkcs1-2048-sha256, rsa-sign-pkcs1-3072-sha256, rsa-sign-pkcs1-4096-sha256) (default "ecdsa-sha2-256-nistp256")
      --signing-config string            path to a signing config file. Must provide --bundle, which will output verification material in the new format
      --sk                               whether to use a hardware security key
      --slot string                      security key slot to use for generated key (default: signature) (authentication|signature|card-authentication|key-management)
      --timestamp-client-cacert string   path to the X.509 CA certificate file in PEM format to be used for the connection to the TSA Server
      --timestamp-client-cert string     path to the X.509 certificate file in PEM format to be used for the connection to the TSA Server
      --timestamp-client-key string      path to the X.509 private key file in PEM format to be used, together with the 'timestamp-client-cert' value, for the connection to the TSA Server
      --timestamp-server-name string     SAN name to use as the 'ServerName' tls.Config field to verify the mTLS connection to the TSA Server
      --timestamp-server-url string      url to the Timestamp RFC3161 server, default none. Must be the path to the API to request timestamp responses, e.g. https://freetsa.org/tsr
      --trusted-root string              optional path to a TrustedRoot JSON file to verify a signature after signing
      --use-signing-config               whether to use a TUF-provided signing config for the service URLs. Must provide --bundle, which will output verification material in the new format (default true)
  -y, --yes                              skip confirmation prompts for non-destructive operations
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -t, --timeout duration     timeout for commands (default 3m0s)
  -d, --verbose              log debug output
```

### SEE ALSO

* [cosign](cosign.md)	 - A tool for Container Signing, Verification and Storage in an OCI registry.

