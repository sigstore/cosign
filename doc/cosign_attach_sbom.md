## cosign attach sbom

DEPRECATED: Attach sbom to the supplied container image

### Synopsis

Attach sbom to the supplied container image

WARNING: SBOM attachments are deprecated and support will be removed in a Cosign release soon after 2024-02-22 (see https://github.com/sigstore/cosign/issues/2755). Instead, please use SBOM attestations.

```
cosign attach sbom [flags]
```

### Examples

```
  cosign attach sbom <image uri>
```

### Options

```
      --allow-http-registry                                                                      whether to allow using HTTP protocol while connecting to registries. Don't use this for anything but testing
      --allow-insecure-registry                                                                  whether to allow insecure connections to registries (e.g., with expired or self-signed TLS certificates). Don't use this for anything but testing
      --attachment-tag-prefix [AttachmentTagPrefix]sha256-[TargetImageDigest].[AttachmentName]   optional custom prefix to use for attached image tags. Attachment images are tagged as: [AttachmentTagPrefix]sha256-[TargetImageDigest].[AttachmentName]
  -h, --help                                                                                     help for sbom
      --input-format string                                                                      type of sbom input format (json|xml|text)
      --k8s-keychain                                                                             whether to use the kubernetes keychain instead of the default keychain (supports workload identity).
      --registry-referrers-mode registryReferrersMode                                            mode for fetching references from the registry. allowed: legacy, oci-1-1
      --sbom string                                                                              path to the sbom, or {-} for stdin
      --type string                                                                              type of sbom (spdx|cyclonedx|syft) (default "spdx")
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -t, --timeout duration     timeout for commands (default 3m0s)
  -d, --verbose              log debug output
```

### SEE ALSO

* [cosign attach](cosign_attach.md)	 - Provides utilities for attaching artifacts to other artifacts in a registry

