## cosign dockerfile verify

Verify a signature on the base image specified in the Dockerfile

### Synopsis

Verify signature and annotations on images in a Dockerfile by checking claims
against the transparency log.

Shell-like variables in the Dockerfile's FROM lines will be substituted with values from the OS ENV.

```
cosign dockerfile verify [flags]
```

### Examples

```
  cosign dockerfile verify --key <key path>|<key url>|<kms uri> <path/to/Dockerfile>

  # verify cosign claims and signing certificates on the FROM images in the Dockerfile
  cosign dockerfile verify <path/to/Dockerfile>

  # only verify the base image (the last FROM image)
  cosign dockerfile verify --base-image-only <path/to/Dockerfile>

  # additionally verify specified annotations
  cosign dockerfile verify -a key1=val1 -a key2=val2 <path/to/Dockerfile>

  # (experimental) additionally, verify with the transparency log
  COSIGN_EXPERIMENTAL=1 cosign dockerfile verify <path/to/Dockerfile>

  # verify images with public key
  cosign dockerfile verify --key cosign.pub <path/to/Dockerfile>

  # verify images with public key provided by URL
  cosign dockerfile verify --key https://host.for/<FILE> <path/to/Dockerfile>

  # verify images with public key stored in Azure Key Vault
  cosign dockerfile verify --key azurekms://[VAULT_NAME][VAULT_URI]/[KEY] <path/to/Dockerfile>

  # verify images with public key stored in AWS KMS
  cosign dockerfile verify --key awskms://[ENDPOINT]/[ID/ALIAS/ARN] <path/to/Dockerfile>

  # verify images with public key stored in Google Cloud KMS
  cosign dockerfile verify --key gcpkms://projects/[PROJECT]/locations/global/keyRings/[KEYRING]/cryptoKeys/[KEY] <path/to/Dockerfile>

  # verify images with public key stored in Hashicorp Vault
  cosign dockerfile verify --key hashivault://[KEY] <path/to/Dockerfile>
```

### Options

```
      --allow-insecure-registry                                                                  whether to allow insecure connections to registries. Don't use this for anything but testing
  -a, --annotations strings                                                                      extra key=value pairs to sign
      --attachment string                                                                        related image attachment to sign (sbom), default none
      --attachment-tag-prefix [AttachmentTagPrefix]sha256-[TargetImageDigest].[AttachmentName]   optional custom prefix to use for attached image tags. Attachment images are tagged as: [AttachmentTagPrefix]sha256-[TargetImageDigest].[AttachmentName]
      --base-image-only                                                                          only verify the base image (the last FROM image in the Dockerfile)
      --cert string                                                                              path to the public certificate
      --cert-email string                                                                        the email expected in a valid fulcio cert
      --check-claims                                                                             whether to check the claims found (default true)
  -h, --help                                                                                     help for verify
      --k8s-keychain                                                                             whether to use the kubernetes keychain instead of the default keychain (supports workload identity).
      --key string                                                                               path to the public key file, KMS URI or Kubernetes Secret
  -o, --output string                                                                            output format for the signing image information (json|text) (default "json")
      --rekor-url string                                                                         [EXPERIMENTAL] address of rekor STL server (default "https://rekor.sigstore.dev")
      --signature string                                                                         signature content or path or remote URL
      --signature-digest-algorithm string                                                        digest algorithm to use when processing a signature (sha224|sha256|sha384|sha512) (default "sha256")
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

* [cosign dockerfile](cosign_dockerfile.md)	 - Provides utilities for discovering images in and performing operations on Dockerfiles

