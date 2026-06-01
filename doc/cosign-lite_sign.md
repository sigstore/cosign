## cosign-lite sign

Sign the supplied payload blob and generate a Sigstore bundle

### Synopsis

Sign the supplied payload blob using a Sigstore OIDC identity token (keyless flow)
or a local on-disk key pair, and generate a standardized Sigstore verification bundle.

```
cosign-lite sign <payload> [flags]
```

### Examples

```
  # Sign a payload keylessly using OIDC and write the bundle to a file
  cosign-lite sign --bundle payload.bundle.json payload.txt

  # Sign a payload using a local private key and write the bundle to a file
  cosign-lite sign --key cosign.key --bundle payload.bundle.json payload.txt

  # Sign a payload using OIDC without uploading to the transparency log (Rekor)
  cosign-lite sign --bundle payload.bundle.json --tlog-upload=false payload.txt
```

### Options

```
      --bundle string                    write everything required to verify the blob to a FILE
      --cert string                      path to the X.509 certificate for signing attestation
      --cert-chain string                path to a list of CA X.509 certificates in PEM format which will be needed when building the certificate chain for the signed attestation. Must start with the parent intermediate CA certificate of the signing certificate and end with the root certificate.
      --fulcio-auth-flow string          fulcio interactive oauth2 flow to use for certificate from fulcio. Defaults to determining the flow based on the runtime environment. (options) normal|device|token|client_credentials
  -h, --help                             help for sign
      --identity-token string            identity token to use for certificate from fulcio. the token or a path to a file containing the token is accepted.
      --issue-certificate                issue a code signing certificate from Fulcio, even if a key is provided
      --key string                       path to the private key file
      --oidc-client-id string            OIDC client ID for application (default "sigstore")
      --oidc-client-secret-file string   Path to file containing OIDC client secret for application
      --oidc-disable-ambient-providers   Disable ambient OIDC providers. When true, ambient credentials will not be read
      --oidc-provider string             Specify the provider to get the OIDC token from (Optional). If unset, all options will be tried. Options include: [spiffe, google, github-actions, filesystem, buildkite-agent]
      --oidc-redirect-url string         OIDC redirect URL (Optional). The default oidc-redirect-url is 'http://localhost:0/auth/callback'.
      --signing-algorithm string         signing algorithm to use for signing/hashing (allowed ecdsa-sha2-256-nistp256, ecdsa-sha2-384-nistp384, ecdsa-sha2-512-nistp521, rsa-sign-pkcs1-2048-sha256, rsa-sign-pkcs1-3072-sha256, rsa-sign-pkcs1-4096-sha256) (default "ecdsa-sha2-256-nistp256")
      --signing-config string            path to a signing config file. Must provide --bundle, which will output verification material in the new format
  -t, --timeout duration                 timeout for commands (default 3m0s)
      --tlog-upload                      whether or not to upload to the tlog (default true)
      --trusted-root string              optional path to a TrustedRoot JSON file to verify a signature after signing
  -y, --yes                              skip confirmation prompts for non-destructive operations
```

### SEE ALSO

* [cosign-lite](cosign-lite.md)	 - cosign-lite is a lightweight Sigstore signing and verification utility

