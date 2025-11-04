## cosign attach signature

Attach signatures to the supplied container image

```
cosign attach signature [flags]
```

### Examples

```
  cosign attach signature [--payload <path>] [--signature < path>] [--rekor-response < path>] <image uri>

		cosign attach signature command attaches payload, signature, rekor-bundle, etc in a new layer of provided image.
		
		# Attach signature can attach payload to a supplied image
		cosign attach signature --payload <payload.json>  $IMAGE

		# Attach signature can attach payload, signature to a supplied image
		cosign attach signature --payload <payload.json> --signature <base64 signature file> $IMAGE

		# Attach signature can attach payload, signature, time stamped response to a supplied image
		cosign attach signature --payload <payload.json> --signature <base64 signature file> --tsr=<file> $IMAGE

		# Attach signature attaches payload, signature and rekor-bundle via rekor-response to a supplied image
		cosign attach signature --payload <payload.json> --signature <base64 signature file>  --rekor-response <proper rekor-response format file> $IMAGE

		# Attach signature attaches payload, signature and rekor-bundle directly to a supplied image
		cosign attach signature --payload <payload.json> --signature <base64 signature file>  --rekor-response <rekor-bundle file> $IMAGE
```

### Options

```
      --allow-http-registry                                                                      whether to allow using HTTP protocol while connecting to registries. Don't use this for anything but testing
      --allow-insecure-registry                                                                  whether to allow insecure connections to registries (e.g., with expired or self-signed TLS certificates). Don't use this for anything but testing
      --attachment-tag-prefix [AttachmentTagPrefix]sha256-[TargetImageDigest].[AttachmentName]   optional custom prefix to use for attached image tags. Attachment images are tagged as: [AttachmentTagPrefix]sha256-[TargetImageDigest].[AttachmentName]
      --bundle string                                                                            path to bundle containing signature (alias for payload)
      --certificate string                                                                       path to the X.509 certificate in PEM format to include in the OCI Signature
      --certificate-chain string                                                                 path to a list of CA X.509 certificates in PEM format which will be needed when building the certificate chain for the signing certificate. Must start with the parent intermediate CA certificate of the signing certificate and end with the root certificate. Included in the OCI Signature
  -h, --help                                                                                     help for signature
      --k8s-keychain                                                                             whether to use the kubernetes keychain instead of the default keychain (supports workload identity).
      --payload string                                                                           path to the payload covered by the signature
      --registry-cacert string                                                                   path to the X.509 CA certificate file in PEM format to be used for the connection to the registry
      --registry-client-cert string                                                              path to the X.509 certificate file in PEM format to be used for the connection to the registry
      --registry-client-key string                                                               path to the X.509 private key file in PEM format to be used, together with the 'registry-client-cert' value, for the connection to the registry
      --registry-password string                                                                 registry basic auth password
      --registry-server-name string                                                              SAN name to use as the 'ServerName' tls.Config field to verify the mTLS connection to the registry
      --registry-token string                                                                    registry bearer auth token
      --registry-username string                                                                 registry basic auth username
      --rekor-response string                                                                    path to the rekor bundle
      --signature string                                                                         path to the signature, or {-} for stdin
      --tsr string                                                                               path to the Time Stamped Signature Response from RFC3161 compliant TSA
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -t, --timeout duration     timeout for commands (default 3m0s)
  -d, --verbose              log debug output
```

### SEE ALSO

* [cosign attach](cosign_attach.md)	 - Provides utilities for attaching artifacts to other artifacts in a registry

