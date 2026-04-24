## cosign verify-blob

Verify a signature on the supplied blob

### Synopsis

Verify a signature on the supplied blob input using the specified key reference.
You may specify either a key, a certificate or a kms reference to verify against.
	If you use a key or a certificate, you must specify the path to them on disk.

The preferred way to provide verification material is via a Sigstore bundle using --bundle,
which contains the signature, certificate, and transparency log proof.
The blob may be specified as a path to a file or - for stdin.

```
cosign verify-blob [flags]
```

### Examples

```
 cosign verify-blob --bundle <bundle path> --certificate-identity <identity> --certificate-oidc-issuer <issuer> <blob>

  # Verify a blob (keyless, Fulcio-issued certificate)
  cosign verify-blob --bundle artifact.sigstore.json --certificate-identity foo@example.com --certificate-oidc-issuer https://token.actions.githubusercontent.com <blob>

  # Verify a blob with an on-disk public key
  cosign verify-blob --bundle artifact.sigstore.json --key cosign.pub <blob>

  # Verify a blob against Azure Key Vault
  cosign verify-blob --bundle artifact.sigstore.json --key azurekms://[VAULT_NAME][VAULT_URI]/[KEY] <blob>

  # Verify a blob against AWS KMS
  cosign verify-blob --bundle artifact.sigstore.json --key awskms://[ENDPOINT]/[ID/ALIAS/ARN] <blob>

  # Verify a blob against Google Cloud KMS
  cosign verify-blob --bundle artifact.sigstore.json --key gcpkms://projects/[PROJECT ID]/locations/[LOCATION]/keyRings/[KEYRING]/cryptoKeys/[KEY] <blob>

  # Verify a blob against Hashicorp Vault
  cosign verify-blob --bundle artifact.sigstore.json --key hashivault://[KEY] <blob>

  # Verify a blob against GitLab with project name
  cosign verify-blob --bundle artifact.sigstore.json --key gitlab://[OWNER]/[PROJECT_NAME] <blob>

  # Verify a blob against GitLab with project id
  cosign verify-blob --bundle artifact.sigstore.json --key gitlab://[PROJECT_ID] <blob>

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
      --experimental-oci11                              set to true to enable experimental OCI 1.1 behaviour (unrelated to bundle format)
  -h, --help                                            help for verify-blob
      --insecure-ignore-sct                             when set, verification will not check that a certificate contains an embedded SCT, a proof of inclusion in a certificate transparency log
      --insecure-ignore-tlog                            ignore transparency log verification, to be used when an artifact signature has not been uploaded to the transparency log. Artifacts cannot be publicly verified when not included in a log
      --key string                                      path to the public key file, KMS URI or Kubernetes Secret
      --max-workers int                                 the amount of maximum workers for parallel executions (default 10)
      --new-bundle-format                               expect the signature/attestation to be packaged in a Sigstore bundle (default true)
      --private-infrastructure                          skip transparency log verification when verifying artifacts in a privately deployed infrastructure
      --sk                                              whether to use a hardware security key
      --slot string                                     security key slot to use for generated key (default: signature) (authentication|signature|card-authentication|key-management)
      --timestamp-certificate-chain string              path to PEM-encoded certificate chain file for the RFC3161 timestamp authority. Must contain the root CA certificate. Optionally may contain intermediate CA certificates, and may contain the leaf TSA certificate if not present in the timestamp
      --trusted-root string                             Path to a Sigstore TrustedRoot JSON file. Requires --new-bundle-format to be set.
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

