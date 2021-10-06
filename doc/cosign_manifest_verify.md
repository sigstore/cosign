## cosign manifest verify

Verify all signatures of images specified in the manifest

### Synopsis

Verify all signature of images in a Kubernetes resource manifest by checking claims
against the transparency log.

```
cosign manifest verify [flags]
```

### Examples

```
  cosign manifest verify --key <key path>|<key url>|<kms uri> <path/to/manifest>

  # verify cosign claims and signing certificates on images in the manifest
  cosign manifest verify <path/to/my-deployment.yaml>

  # additionally verify specified annotations
  cosign manifest verify -a key1=val1 -a key2=val2 <path/to/my-deployment.yaml>

  # (experimental) additionally, verify with the transparency log
  COSIGN_EXPERIMENTAL=1 cosign manifest verify <path/to/my-deployment.yaml>

  # verify images with public key
  cosign manifest verify --key cosign.pub <path/to/my-deployment.yaml>

  # verify images with public key provided by URL
  cosign manifest verify --key https://host.for/<FILE> <path/to/my-deployment.yaml>

  # verify images with public key stored in Azure Key Vault
  cosign manifest verify --key azurekms://[VAULT_NAME][VAULT_URI]/[KEY] <path/to/my-deployment.yaml>

  # verify images with public key stored in AWS KMS
  cosign manifest verify --key awskms://[ENDPOINT]/[ID/ALIAS/ARN] <path/to/my-deployment.yaml>

  # verify images with public key stored in Google Cloud KMS
  cosign manifest verify --key gcpkms://projects/[PROJECT]/locations/global/keyRings/[KEYRING]/cryptoKeys/[KEY] <path/to/my-deployment.yaml>

  # verify images with public key stored in Hashicorp Vault
  cosign manifest verify --key hashivault://[KEY] <path/to/my-deployment.yaml>
```

### Options

```
      --allow-insecure-registry   whether to allow insecure connections to registries. Don't use this for anything but testing
  -a, --annotations strings       extra key=value pairs to sign
      --attachment string         related image attachment to sign (sbom), default none
      --cert-email string         the email expected in a valid fulcio cert
      --check-claims              whether to check the claims found (default true)
  -h, --help                      help for verify
      --key string                path to the private key file, KMS URI or Kubernetes Secret
  -o, --output string             output format for the signing image information (json|text) (default "json")
      --rekor-url string          [EXPERIMENTAL] address of rekor STL server (default "https://rekor.sigstore.dev")
      --sk                        whether to use a hardware security key
      --slot string               security key slot to use for generated key (default: signature) (authentication|signature|card-authentication|key-management)
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -v, --verbose              log verbose debug output
```

### SEE ALSO

* [cosign manifest](cosign_manifest.md)	 - Provides utilities for discovering images in and performing operations on Kubernetes manifests

