// Go version
variable "GO_VERSION" {
  default = "1.16"
}

target "go-version" {
  args = {
    GO_VERSION = GO_VERSION
  }
}

// GitHub reference as defined in GitHub Actions (eg. refs/head/master)
variable "GITHUB_REF" {
  default = ""
}

target "git-ref" {
  args = {
    GIT_REF = GITHUB_REF
  }
}

group "default" {
  targets = ["artifact"]
}

group "validate" {
  targets = ["lint", "vendor-validate"]
}

target "lint" {
  inherits = ["go-version"]
  dockerfile = "./hack/lint.Dockerfile"
  target = "lint"
}

target "license-check" {
  inherits = ["go-version"]
  dockerfile = "./hack/license.Dockerfile"
  target = "check"
}

target "license-update" {
  inherits = ["go-version"]
  dockerfile = "./hack/license.Dockerfile"
  target = "update"
}

target "vendor-validate" {
  inherits = ["go-version"]
  dockerfile = "./hack/vendor.Dockerfile"
  target = "validate"
}

target "vendor-update" {
  inherits = ["go-version"]
  dockerfile = "./hack/vendor.Dockerfile"
  target = "update"
  output = ["."]
}

target "test" {
  inherits = ["go-version"]
  dockerfile = "./hack/test.Dockerfile"
  target = "test"
  output = ["."]
}

target "artifact" {
  inherits = ["go-version", "git-ref"]
  dockerfile = "./hack/build.Dockerfile"
  target = "artifacts"
  output = ["./bin"]
}

target "artifact-all" {
  inherits = ["artifact"]
  dockerfile = "./hack/build.Dockerfile"
  platforms = [
    "darwin/amd64",
    "darwin/arm64",
    "linux/amd64",
    "linux/arm/v5",
    "linux/arm/v6",
    "linux/arm/v7",
    "linux/arm64",
    "linux/386",
    "linux/ppc64le",
    "linux/s390x",
    "windows/amd64",
    "windows/386"
  ]
}
