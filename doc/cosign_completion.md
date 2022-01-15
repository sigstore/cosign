## cosign completion

Generate completion script

### Synopsis

To load completions:
Bash:
  $ source <(cosign completion bash)
  # To load completions for each session, execute once:
  # Linux:
  $ cosign completion bash > /etc/bash_completion.d/cosign
  # macOS:
  $ cosign completion bash > /usr/local/etc/bash_completion.d/cosign
Zsh:
  # If shell completion is not already enabled in your environment,
  # you will need to enable it.  You can execute the following once:
  $ echo "autoload -U compinit; compinit" >> ~/.zshrc
  # To load completions for each session, execute once:
  $ cosign completion zsh > "${fpath[1]}/_cosign"
  # You will need to start a new shell for this setup to take effect.
fish:
  $ cosign completion fish | source
  # To load completions for each session, execute once:
  $ cosign completion fish > ~/.config/fish/completions/cosign.fish
PowerShell:
  PS> cosign completion powershell | Out-String | Invoke-Expression
  # To load completions for every new session, run:
  PS> cosign completion powershell > cosign.ps1
  # and source this file from your PowerShell profile.


```
cosign completion [bash|zsh|fish|powershell]
```

### Options

```
  -h, --help   help for completion
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -d, --verbose              log debug output
```

### SEE ALSO

* [cosign](cosign.md)	 - 

