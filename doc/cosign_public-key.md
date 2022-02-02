## cosign public-key

Gets a public key from the key-pair.

### Synopsis

Gets a public key from the key-pair and
writes to a specified file. By default, it will write to standard out.

```
cosign public-key [flags]
```

### Examples

```

  # extract public key from private key to a specified out file.
  cosign public-key --key <PRIVATE KEY FILE> --outfile <OUTPUT>

  # extract public key from URL.
  cosign public-key --key https://host.for/<FILE> --outfile <OUTPUT>

  # extract public key from Azure Key Vault
  cosign public-key --key azurekms://[VAULT_NAME][VAULT_URI]/[KEY]

  # extract public key from AWS KMS
  cosign public-key --key awskms://[ENDPOINT]/[ID/ALIAS/ARN]

  # extract public key from Google Cloud KMS
  cosign public-key --key gcpkms://projects/[PROJECT]/locations/global/keyRings/[KEYRING]/cryptoKeys/[KEY]

  # extract public key from Hashicorp Vault KMS
  cosign public-key --key hashivault://[KEY]

  # extract public key from GitLab with project name
  cosign verify --key gitlab://[OWNER]/[PROJECT_NAME] <IMAGE>

  # extract public key from GitLab with project id
  cosign verify --key gitlab://[PROJECT_ID] <IMAGE>
```

### Options

```
  -h, --help             help for public-key
      --key string       path to the private key file, KMS URI or Kubernetes Secret
      --outfile string   path to a payload file to use rather than generating one
      --sk               whether to use a hardware security key
      --slot string      security key slot to use for generated key (default: signature) (authentication|signature|card-authentication|key-management)
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -t, --timeout duration     timeout for commands (default 3m0s)
  -d, --verbose              log debug output
```

### SEE ALSO

* [cosign](cosign.md)	 - 

