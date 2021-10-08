## cosign policy sign

sign a keyless policy.

### Synopsis

policy is used to manage a root.json policy
for keyless signing delegation. This is used to establish a policy for a registry namespace,
a signing threshold and a list of maintainers who can sign over the body section.

```
cosign policy sign [flags]
```

### Options

```
      --allow-insecure-registry     whether to allow insecure connections to registries. Don't use this for anything but testing
      --fulcio-url string           [EXPERIMENTAL] address of sigstore PKI server (default "https://fulcio.sigstore.dev")
  -h, --help                        help for sign
      --identity-token string       [EXPERIMENTAL] identity token to use for certificate from fulcio
      --namespace string            registry namespace that the root policy belongs to (default "ns")
      --oidc-client-id string       [EXPERIMENTAL] OIDC client ID for application (default "sigstore")
      --oidc-client-secret string   [EXPERIMENTAL] OIDC client secret for application
      --oidc-issuer string          [EXPERIMENTAL] OIDC provider to be used to issue ID token (default "https://oauth2.sigstore.dev/auth")
      --out string                  output policy locally (default "o")
      --rekor-url string            [EXPERIMENTAL] address of rekor STL server (default "https://rekor.sigstore.dev")
      --tag-prefix string           custom prefix to use for tags
      --tag-suffix string           custom suffix to use for tags
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -d, --verbose              log debug output
```

### SEE ALSO

* [cosign policy](cosign_policy.md)	 - subcommand to manage a keyless policy.

