## cosign policy init

generate a new keyless policy.

### Synopsis

init is used to generate a root.json policy
for keyless signing delegation. This is used to establish a policy for a registry namespace,
a signing threshold and a list of maintainers who can sign over the body section.

```
cosign policy init [flags]
```

### Examples

```

  # extract public key from private key to a specified out file.
  cosign policy init -ns <project_namespace> --maintainers {email_addresses} --threshold <int> --expires <int>(days)
```

### Options

```
      --allow-insecure-registry                                                                  whether to allow insecure connections to registries. Don't use this for anything but testing
      --attachment-tag-prefix [AttachmentTagPrefix]sha256-[TargetImageDigest].[AttachmentName]   optional custom prefix to use for attached image tags. Attachment images are tagged as: [AttachmentTagPrefix]sha256-[TargetImageDigest].[AttachmentName]
      --expires int                                                                              total expire duration in days
  -h, --help                                                                                     help for init
      --k8s-keychain                                                                             whether to use the kubernetes keychain instead of the default keychain (supports workload identity).
  -m, --maintainers strings                                                                      list of maintainers to add to the root policy
      --namespace string                                                                         registry namespace that the root policy belongs to (default "ns")
      --out string                                                                               output policy locally (default "o")
      --threshold int                                                                            threshold for root policy signers (default 1)
```

### Options inherited from parent commands

```
      --azure-container-registry-config string   Path to the file containing Azure container registry configuration information.
      --output-file string                       log output to a file
  -d, --verbose                                  log debug output
```

### SEE ALSO

* [cosign policy](cosign_policy.md)	 - subcommand to manage a keyless policy.

