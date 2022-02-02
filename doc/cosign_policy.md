## cosign policy

subcommand to manage a keyless policy.

### Synopsis

policy is used to manage a root.json policy
for keyless signing delegation. This is used to establish a policy for a registry namespace,
a signing threshold and a list of maintainers who can sign over the body section.

```
cosign policy [flags]
```

### Options

```
  -h, --help   help for policy
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -t, --timeout duration     timeout for commands (default 3m0s)
  -d, --verbose              log debug output
```

### SEE ALSO

* [cosign](cosign.md)	 - 
* [cosign policy init](cosign_policy_init.md)	 - generate a new keyless policy.
* [cosign policy sign](cosign_policy_sign.md)	 - sign a keyless policy.

