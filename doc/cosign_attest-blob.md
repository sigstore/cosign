## cosign attest-blob

Attest the supplied blob.

```
cosign attest-blob [flags]
```

### Examples

```
  cosign attest-blob --key <key path>|<kms uri> [--predicate <path>] [--a key=value] [--f] [--r] <BLOB uri>

  # attach an attestation to a blob with a local key pair file and print the attestation
  cosign attest-blob --predicate <FILE> --type <TYPE> --key cosign.key --output-attestation <path> <BLOB>

  # attach an attestation to a blob with a key pair stored in Azure Key Vault
  cosign attest-blob --predicate <FILE> --type <TYPE> --key azurekms://[VAULT_NAME][VAULT_URI]/[KEY] <BLOB>

  # attach an attestation to a blob with a key pair stored in AWS KMS
  cosign attest-blob --predicate <FILE> --type <TYPE> --key awskms://[ENDPOINT]/[ID/ALIAS/ARN] <BLOB>

  # attach an attestation to a blob with a key pair stored in Google Cloud KMS
  cosign attest-blob --predicate <FILE> --type <TYPE> --key gcpkms://projects/[PROJECT]/locations/global/keyRings/[KEYRING]/cryptoKeys/[KEY]/versions/[VERSION] <BLOB>

  # attach an attestation to a blob with a key pair stored in Hashicorp Vault
  cosign attest-blob --predicate <FILE> --type <TYPE> --key hashivault://[KEY] <BLOB>
```

### Options

```
      --bundle string                     write everything required to verify the blob to a FILE
      --certificate string                path to the X.509 certificate in PEM format to include in the OCI Signature
      --certificate-chain string          path to a list of CA X.509 certificates in PEM format which will be needed when building the certificate chain for the signing certificate. Must start with the parent intermediate CA certificate of the signing certificate and end with the root certificate. Included in the OCI Signature
      --fulcio-url string                 [EXPERIMENTAL] address of sigstore PKI server (default "https://fulcio.sigstore.dev")
      --hash string                       hash of blob in hexadecimal (base16). Used if you want to sign an artifact stored elsewhere and have the hash
  -h, --help                              help for attest-blob
      --identity-token string             [EXPERIMENTAL] identity token to use for certificate from fulcio. the token or a path to a file containing the token is accepted.
      --insecure-skip-verify              [EXPERIMENTAL] skip verifying fulcio published to the SCT (this should only be used for testing).
      --key string                        path to the private key file, KMS URI or Kubernetes Secret
      --oidc-client-id string             [EXPERIMENTAL] OIDC client ID for application (default "sigstore")
      --oidc-client-secret-file string    [EXPERIMENTAL] Path to file containing OIDC client secret for application
      --oidc-disable-ambient-providers    [EXPERIMENTAL] Disable ambient OIDC providers. When true, ambient credentials will not be read
      --oidc-issuer string                [EXPERIMENTAL] OIDC provider to be used to issue ID token (default "https://oauth2.sigstore.dev/auth")
      --oidc-provider string              [EXPERIMENTAL] Specify the provider to get the OIDC token from (Optional). If unset, all options will be tried. Options include: [spiffe, google, github, filesystem]
      --oidc-redirect-url string          [EXPERIMENTAL] OIDC redirect URL (Optional). The default oidc-redirect-url is 'http://localhost:0/auth/callback'.
      --output-attestation string         write the attestation to FILE
      --output-certificate string         write the certificate to FILE
      --output-signature string           write the signature to FILE
      --predicate string                  path to the predicate file.
      --rekor-url string                  [EXPERIMENTAL] address of rekor STL server (default "https://rekor.sigstore.dev")
      --rfc3161-timestamp-bundle string   path to an RFC 3161 timestamp bundle FILE
      --sk                                whether to use a hardware security key
      --slot string                       security key slot to use for generated key (default: signature) (authentication|signature|card-authentication|key-management)
      --timestamp-server-url string       url to the Timestamp RFC3161 server, default none
      --tlog-upload                       whether or not to upload to the tlog (default true)
      --type string                       specify a predicate type (slsaprovenance|link|spdx|spdxjson|cyclonedx|vuln|custom) or an URI (default "custom")
  -y, --yes                               skip confirmation prompts for non-destructive operations
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -t, --timeout duration     timeout for commands (default 3m0s)
  -d, --verbose              log debug output
```

### SEE ALSO

* [cosign](cosign.md)	 - A tool for Container Signing, Verification and Storage in an OCI registry.

