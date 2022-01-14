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
  cosign verify-blob (--key <key path>|<key url>|<kms uri>)|(--cert <cert>) --signature <sig> <blob>

  # Verify a simple blob and message
  cosign verify-blob --key cosign.pub --signature sig msg

  # Verify a simple blob with remote signature URL, both http and https schemes are supported
  cosign verify-blob --key cosign.pub --signature http://host/my.sig

  # Verify a signature from an environment variable
  cosign verify-blob --key cosign.pub --signature $sig msg

  # verify a signature with public key provided by URL
  cosign verify-blob --key https://host.for/<FILE> --signature $sig msg

  # Verify a signature against a payload from another process using process redirection
  cosign verify-blob --key cosign.pub --signature $sig <(git rev-parse HEAD)

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
  cosign verify-blob --cert <cert> --signature $sig <blob>

```

### Options

```
      --allow-insecure-registry                                                                  whether to allow insecure connections to registries. Don't use this for anything but testing
      --attachment-tag-prefix [AttachmentTagPrefix]sha256-[TargetImageDigest].[AttachmentName]   optional custom prefix to use for attached image tags. Attachment images are tagged as: [AttachmentTagPrefix]sha256-[TargetImageDigest].[AttachmentName]
      --cert string                                                                              path to the public certificate
      --cert-email string                                                                        the email expected in a valid Fulcio certificate
      --cert-oidc-issuer string                                                                  the OIDC issuer expected in a valid Fulcio certificate, e.g. https://token.actions.githubusercontent.com or https://oauth2.sigstore.dev/auth
  -h, --help                                                                                     help for verify-blob
      --k8s-keychain                                                                             whether to use the kubernetes keychain instead of the default keychain (supports workload identity).
      --key string                                                                               path to the public key file, KMS URI or Kubernetes Secret
      --rekor-url string                                                                         [EXPERIMENTAL] address of rekor STL server (default "https://rekor.sigstore.dev")
      --signature string                                                                         signature content or path or remote URL
      --sk                                                                                       whether to use a hardware security key
      --slot string                                                                              security key slot to use for generated key (default: signature) (authentication|signature|card-authentication|key-management)
```

### Options inherited from parent commands

```
      --azure-container-registry-config string   Path to the file containing Azure container registry configuration information.
      --output-file string                       log output to a file
  -d, --verbose                                  log debug output
```

### SEE ALSO

* [cosign](cosign.md)	 - 

