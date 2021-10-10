## cosign generate-key-pair

Generates a key-pair.

### Synopsis

Generates a key-pair for signing.

```
cosign generate-key-pair [flags]
```

### Examples

```
  cosign generate-key-pair [--kms KMSPATH]

  # generate key-pair and write to cosign.key and cosign.pub files
  cosign generate-key-pair

  # generate a key-pair in Azure Key Vault
  cosign generate-key-pair --kms azurekms://[VAULT_NAME][VAULT_URI]/[KEY]

  # generate a key-pair in AWS KMS
  cosign generate-key-pair --kms awskms://[ENDPOINT]/[ID/ALIAS/ARN]

  # generate a key-pair in Google Cloud KMS
  cosign generate-key-pair --kms gcpkms://projects/[PROJECT]/locations/global/keyRings/[KEYRING]/cryptoKeys/[KEY]

  # generate a key-pair in Hashicorp Vault
  cosign generate-key-pair --kms hashivault://[KEY]

  # generate a key-pair in Kubernetes Secret
  cosign generate-key-pair k8s://[NAMESPACE]/[NAME]

  # generate a key-pair in GitHub
  cosign generate-key-pair github://owner/project

  # generate a key-pair in GitLab
  cosign generate-key-pair gitlab://owner/project

CAVEATS:
  This command interactively prompts for a password. You can use
  the COSIGN_PASSWORD environment variable to provide one.
```

### Options

```
  -h, --help         help for generate-key-pair
      --kms string   create key pair in KMS service to use for signing
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -d, --verbose              log debug output
```

### SEE ALSO

* [cosign](cosign.md)	 - 

