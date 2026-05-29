## cosign-verify verify-attestation

Verify a signed in-toto statement and output its payload to stdout

### Synopsis

Verify a signed in-toto statement wrapped in a DSSE envelope inside a standard Sigstore bundle.
Outputs the verified JSON statement to stdout.

```
cosign-verify verify-attestation [payload-file] [flags]
```

### Examples

```
  # Verify an attestation using a local public key
  cosign-verify verify-attestation --bundle statement.bundle.json --key cosign.pub

  # Verify and assert the statement describes a specific local file
  cosign-verify verify-attestation --bundle statement.bundle.json --key cosign.pub payload.txt
```

### Options

```
      --bundle string                                   path to bundle FILE
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
  -h, --help                                            help for verify-attestation
      --insecure-ignore-sct                             when set, verification will not check that a certificate contains an embedded SCT, a proof of inclusion in a certificate transparency log
      --insecure-ignore-tlog                            ignore transparency log verification, to be used when an artifact signature has not been uploaded to the transparency log. Artifacts cannot be publicly verified when not included in a log
      --key string                                      path to the public key file
      --offline                                         only verify an artifact's inclusion in a transparency log using a provided proof, rather than querying the log. May still include network requests to retrieve service keys from a TUF repository
      --predicate-type string                           specify a predicate type (slsaprovenance|slsaprovenance02|slsaprovenance1|link|spdx|spdxjson|cyclonedx|vuln|openvex|custom) or an URI (default "custom")
  -t, --timeout duration                                timeout for commands (default 3m0s)
      --trusted-root string                             Path to a Sigstore TrustedRoot JSON file.
      --use-signed-timestamps                           verify rfc3161 timestamps
```

### SEE ALSO

* [cosign-verify](cosign-verify.md)	 - cosign-verify is a minimal verification utility for Sigstore

