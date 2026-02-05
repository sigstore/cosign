## cosign verify-blob-attestation

Verify an attestation on the supplied blob

### Synopsis

Verify an attestation on the supplied blob input using the specified key reference.
You may specify either a key or a kms reference to verify against.

The signature may be specified as a path to a file or a base64 encoded string.
The blob may be specified as a path to a file.

```
cosign verify-blob-attestation [flags]
```

### Examples

```
 cosign verify-blob-attestation (--key <key path>|<key url>|<kms uri>) --signature <sig> [path to BLOB]

  # Verify a simple blob attestation with a DSSE style signature
  cosign verify-blob-attestation --key cosign.pub (--signature <sig path>|<sig url>)[path to BLOB]


```

### Options

```
      --bundle string                                   path to bundle FILE
      --ca-intermediates string                         path to a file of intermediate CA certificates in PEM format which will be needed when building the certificate chains for the signing certificate. The flag is optional and must be used together with --ca-roots, conflicts with --certificate-chain.
      --ca-roots string                                 path to a bundle file of CA certificates in PEM format which will be needed when building the certificate chains for the signing certificate. Conflicts with --certificate-chain.
      --certificate string                              path to the public certificate. The certificate will be verified against the Fulcio roots if the --certificate-chain option is not passed.
      --certificate-chain string                        path to a list of CA certificates in PEM format which will be needed when building the certificate chain for the signing certificate. Must start with the parent intermediate CA certificate of the signing certificate and end with the root certificate. Conflicts with --ca-roots and --ca-intermediates.
      --certificate-github-workflow-name string         contains the workflow claim from the GitHub OIDC Identity token that contains the name of the executed workflow.
      --certificate-github-workflow-ref string          contains the ref claim from the GitHub OIDC Identity token that contains the git ref that the workflow run was based upon.
      --certificate-github-workflow-repository string   contains the repository claim from the GitHub OIDC Identity token that contains the repository that the workflow run was based upon
      --certificate-github-workflow-sha string          contains the sha claim from the GitHub OIDC Identity token that contains the commit SHA that the workflow run was based upon.
      --certificate-github-workflow-trigger string      contains the event_name claim from the GitHub OIDC Identity token that contains the name of the event that triggered the workflow run
      --certificate-identity string                     The identity expected in a valid Fulcio certificate. Valid values include email address, DNS names, IP addresses, and URIs. Either --certificate-identity or --certificate-identity-regexp must be set for keyless flows.
      --certificate-identity-regexp string              A regular expression alternative to --certificate-identity. Accepts the Go regular expression syntax described at https://golang.org/s/re2syntax. Either --certificate-identity or --certificate-identity-regexp must be set for keyless flows.
      --certificate-oidc-issuer string                  The OIDC issuer expected in a valid Fulcio certificate, e.g. https://token.actions.githubusercontent.com or https://oauth2.sigstore.dev/auth. Either --certificate-oidc-issuer or --certificate-oidc-issuer-regexp must be set for keyless flows.
      --certificate-oidc-issuer-regexp string           A regular expression alternative to --certificate-oidc-issuer. Accepts the Go regular expression syntax described at https://golang.org/s/re2syntax. Either --certificate-oidc-issuer or --certificate-oidc-issuer-regexp must be set for keyless flows.
      --check-claims                                    if true, verifies the digest exists in the in-toto subject (using either the provided digest and digest algorithm or the provided blob's sha256 digest). If false, only the DSSE envelope is verified. (default true)
      --digest string                                   Digest to use for verifying in-toto subject (instead of providing a blob)
      --digestAlg string                                Digest algorithm to use for verifying in-toto subject (instead of providing a blob)
      --experimental-oci11                              set to true to enable experimental OCI 1.1 behaviour (unrelated to bundle format)
  -h, --help                                            help for verify-blob-attestation
      --insecure-ignore-sct                             when set, verification will not check that a certificate contains an embedded SCT, a proof of inclusion in a certificate transparency log
      --insecure-ignore-tlog                            ignore transparency log verification, to be used when an artifact signature has not been uploaded to the transparency log. Artifacts cannot be publicly verified when not included in a log
      --key string                                      path to the public key file, KMS URI or Kubernetes Secret
      --max-workers int                                 the amount of maximum workers for parallel executions (default 10)
      --new-bundle-format                               expect the signature/attestation to be packaged in a Sigstore bundle (default true)
      --private-infrastructure                          skip transparency log verification when verifying artifacts in a privately deployed infrastructure
      --rekor-url string                                address of rekor STL server (default "https://rekor.sigstore.dev")
      --rekor-version uint32                            version of rekor API (default 1)
      --rfc3161-timestamp string                        path to RFC3161 timestamp FILE
      --sct string                                      path to a detached Signed Certificate Timestamp, formatted as a RFC6962 AddChainResponse struct. If a certificate contains an SCT, verification will check both the detached and embedded SCTs.
      --signature string                                path to base64-encoded signature over attestation in DSSE format
      --signature-digest-algorithm string               digest algorithm to use when processing a signature (sha224|sha256|sha384|sha512) (default "sha256")
      --sk                                              whether to use a hardware security key
      --slot string                                     security key slot to use for generated key (default: signature) (authentication|signature|card-authentication|key-management)
      --timestamp-certificate-chain string              path to PEM-encoded certificate chain file for the RFC3161 timestamp authority. Must contain the root CA certificate. Optionally may contain intermediate CA certificates, and may contain the leaf TSA certificate if not present in the timestamp
      --trusted-root string                             Path to a Sigstore TrustedRoot JSON file. Requires --new-bundle-format to be set.
      --type string                                     specify a predicate type (slsaprovenance|slsaprovenance02|slsaprovenance1|link|spdx|spdxjson|cyclonedx|vuln|openvex|custom) or an URI (default "custom")
      --use-signed-timestamps                           verify rfc3161 timestamps
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -t, --timeout duration     timeout for commands (default 3m0s)
  -d, --verbose              log debug output
```

### SEE ALSO

* [cosign](cosign.md)	 - A tool for Container Signing, Verification and Storage in an OCI registry.

