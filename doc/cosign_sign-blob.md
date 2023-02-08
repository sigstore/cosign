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
      --fulcio-url string                [EXPERIMENTAL] address of sigstore PKI server (default "https://fulcio.sigstore.dev")
  -h, --help                             help for sign-blob
      --identity-token string            [EXPERIMENTAL] identity token to use for certificate from fulcio. the token or a path to a file containing the token is accepted.
      --insecure-skip-verify             [EXPERIMENTAL] skip verifying fulcio published to the SCT (this should only be used for testing).
      --issue-certificate                issue a code signing certificate from Fulcio, even if a key is provided
      --key string                       path to the private key file, KMS URI or Kubernetes Secret
      --oidc-client-id string            [EXPERIMENTAL] OIDC client ID for application (default "sigstore")
      --oidc-client-secret-file string   [EXPERIMENTAL] Path to file containing OIDC client secret for application
      --oidc-disable-ambient-providers   [EXPERIMENTAL] Disable ambient OIDC providers. When true, ambient credentials will not be read
      --oidc-issuer string               [EXPERIMENTAL] OIDC provider to be used to issue ID token (default "https://oauth2.sigstore.dev/auth")
      --oidc-provider string             [EXPERIMENTAL] Specify the provider to get the OIDC token from (Optional). If unset, all options will be tried. Options include: [spiffe, google, github, filesystem]
      --oidc-redirect-url string         [EXPERIMENTAL] OIDC redirect URL (Optional). The default oidc-redirect-url is 'http://localhost:0/auth/callback'.
      --output string                    write the signature to FILE
      --output-certificate string        write the certificate to FILE
      --output-signature string          write the signature to FILE
      --rekor-url string                 [EXPERIMENTAL] address of rekor STL server (default "https://rekor.sigstore.dev")
      --rfc3161-timestamp string         write the RFC3161 timestamp to a file
      --sk                               whether to use a hardware security key
      --slot string                      security key slot to use for generated key (default: signature) (authentication|signature|card-authentication|key-management)
      --timestamp-server-url string      url to the Timestamp RFC3161 server, default none
      --tlog-upload                      whether or not to upload to the tlog (default true)
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

