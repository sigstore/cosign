## cosign verify-blob

Verify a signature on the supplied blob

### Synopsis

Verify a signature on the supplied blob input using the specified key reference.
You may specify either a key, a certificate or a kms reference to verify against.
	If you use a key or a certificate, you must specify the path to them on disk.

The signature may be specified as a path to a file or a base64 encoded string.
The blob may be specified as a path to a file or - for stdin.

```
cosign verify-blob [flags]
```

### Examples

```
 cosign verify-blob (--key <key path>|<key url>|<kms uri>)|(--certificate <cert>) --signature <sig> <blob>

  # Verify a simple blob and message
  cosign verify-blob --key cosign.pub (--signature <sig path>|<sig url> msg)

  # Verify a signature from an environment variable
  cosign verify-blob --key cosign.pub --signature $sig msg

  # verify a signature with public key provided by URL
  cosign verify-blob --key https://host.for/<FILE> --signature $sig msg

  # verify a signature with signature and key provided by URL
  cosign verify-blob --key https://host.for/<FILE> --signature https://example.com/<SIG>

  # Verify a signature against Azure Key Vault
  cosign verify-blob --key azurekms://[VAULT_NAME][VAULT_URI]/[KEY] --signature $sig <blob>

  # Verify a signature against AWS KMS
  cosign verify-blob --key awskms://[ENDPOINT]/[ID/ALIAS/ARN] --signature $sig <blob>

  # Verify a signature against Google Cloud KMS
  cosign verify-blob --key gcpkms://projects/[PROJECT ID]/locations/[LOCATION]/keyRings/[KEYRING]/cryptoKeys/[KEY] --signature $sig <blob>

  # Verify a signature against Hashicorp Vault
  cosign verify-blob --key hashivault://[KEY] --signature $sig <blob>

  # Verify a signature against GitLab with project name
  cosign verify-blob --key gitlab://[OWNER]/[PROJECT_NAME]  --signature $sig <blob>

  # Verify a signature against GitLab with project id
  cosign verify-blob --key gitlab://[PROJECT_ID]  --signature $sig <blob>

  # Verify a signature against a certificate
  cosign verify-blob --certificate <cert> --signature $sig <blob>

```

### Options

```
      --bundle string                                   path to bundle FILE
      --certificate string                              path to the public certificate. The certificate will be verified against the Fulcio roots if the --certificate-chain option is not passed.
      --certificate-chain string                        path to a list of CA certificates in PEM format which will be needed when building the certificate chain for the signing certificate. Must start with the parent intermediate CA certificate of the signing certificate and end with the root certificate
      --certificate-github-workflow-name string         contains the workflow claim from the GitHub OIDC Identity token that contains the name of the executed workflow.
      --certificate-github-workflow-ref string          contains the ref claim from the GitHub OIDC Identity token that contains the git ref that the workflow run was based upon.
      --certificate-github-workflow-repository string   contains the repository claim from the GitHub OIDC Identity token that contains the repository that the workflow run was based upon
      --certificate-github-workflow-sha string          contains the sha claim from the GitHub OIDC Identity token that contains the commit SHA that the workflow run was based upon.
      --certificate-github-workflow-trigger string      contains the event_name claim from the GitHub OIDC Identity token that contains the name of the event that triggered the workflow run
      --certificate-identity string                     The identity expected in a valid Fulcio certificate. Valid values include email address, DNS names, IP addresses, and URIs. Either --certificate-identity or --certificate-identity-regexp must be set for keyless flows.
      --certificate-identity-regexp string              A regular expression alternative to --certificate-identity. Accepts the Go regular expression syntax described at https://golang.org/s/re2syntax. Either --certificate-identity or --certificate-identity-regexp must be set for keyless flows.
      --certificate-oidc-issuer string                  The OIDC issuer expected in a valid Fulcio certificate, e.g. https://token.actions.githubusercontent.com or https://oauth2.sigstore.dev/auth. Either --certificate-oidc-issuer or --certificate-oidc-issuer-regexp must be set for keyless flows.
      --certificate-oidc-issuer-regexp string           A regular expression alternative to --certificate-oidc-issuer. Accepts the Go regular expression syntax described at https://golang.org/s/re2syntax. Either --certificate-oidc-issuer or --certificate-oidc-issuer-regexp must be set for keyless flows.
      --experimental-oci11                              set to true to enable experimental OCI 1.1 behaviour
  -h, --help                                            help for verify-blob
      --insecure-ignore-sct                             when set, verification will not check that a certificate contains an embedded SCT, a proof of inclusion in a certificate transparency log
      --insecure-ignore-tlog                            ignore transparency log verification, to be used when an artifact signature has not been uploaded to the transparency log. Artifacts cannot be publicly verified when not included in a log
      --key string                                      path to the public key file, KMS URI or Kubernetes Secret
      --max-workers int                                 the amount of maximum workers for parallel executions (default 10)
      --offline                                         only allow offline verification
      --rekor-url string                                address of rekor STL server (default "https://rekor.sigstore.dev")
      --rfc3161-timestamp string                        path to RFC3161 timestamp FILE
      --sct string                                      path to a detached Signed Certificate Timestamp, formatted as a RFC6962 AddChainResponse struct. If a certificate contains an SCT, verification will check both the detached and embedded SCTs.
      --signature string                                signature content or path or remote URL
      --sk                                              whether to use a hardware security key
      --slot string                                     security key slot to use for generated key (default: signature) (authentication|signature|card-authentication|key-management)
      --timestamp-certificate-chain string              path to PEM-encoded certificate chain file for the RFC3161 timestamp authority. Must contain the root CA certificate. Optionally may contain intermediate CA certificates, and may contain the leaf TSA certificate if not present in the timestamp
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -t, --timeout duration     timeout for commands (default 3m0s)
  -d, --verbose              log debug output
```

### SEE ALSO

* [cosign](cosign.md)	 - A tool for Container Signing, Verification and Storage in an OCI registry.

