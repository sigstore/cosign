## Expected `cosign version` Behaviour
From version 2.1.0 (as part of a [dependency update](https://github.com/sigstore/cosign/commit/40dbbd8b09bd5c30191d6e7e7ced3bbd7f6ea559)), the version metadata is [printed to standard output](https://github.com/kubernetes-sigs/release-utils/pull/76). By default it includes the package version, commit hash, git tree state, build date, Go version, compiler toolchain and current platform.

### ASCII Output
The output of `cosign version` is expected to resemble this format, with the specific values being appropriate for each build of the `cosign` package.

```
$ cosign version
  ______   ______        _______. __    _______ .__   __.
 /      | /  __  \      /       ||  |  /  _____||  \ |  |
|  ,----'|  |  |  |    |   (----`|  | |  |  __  |   \|  |
|  |     |  |  |  |     \   \    |  | |  | |_ | |  . `  |
|  `----.|  `--'  | .----)   |   |  | |  |__| | |  |\   |
 \______| \______/  |_______/    |__|  \______| |__| \__|
cosign: A tool for Container Signing, Verification and Storage in an OCI registry.

GitVersion:    [vX.Y.Z or devel]
GitCommit:     [hash or unknown]
GitTreeState:  [clean or dirty]
BuildDate:     [yyyy-MM-ddThh:mm:ss or unknown]
GoVersion:     go1.A.B
Compiler:      gc
Platform:      os/arch
```

### JSON Output
The output of `cosign version --json` is expected to resemble this format, with the specific values being appropriate for each build of the `cosign` package.

```
$ cosign version --json
{
  "gitVersion": "[vX.Y.Z or devel]",
  "gitCommit": "[hash or unknown]",
  "gitTreeState": "[clean or dirty]",
  "buildDate": "[yyyy-MM-ddThh:mm:ss or unknown]",
  "goVersion": "go1.A.B",
  "compiler": "gc",
  "platform": "os/arch"
}
```