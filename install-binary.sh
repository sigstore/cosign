#!/usr/bin/env bash

# verifySupported checks that the os/arch combination is supported for
# binary builds.
verifySupported() {
  supported="\nlinux-amd64\nlinux-arm64\ndarwin-amd64\ndarwin-arm64\nwindows-amd64"
  if ! echo "${supported}" | grep -q "${OS}-${ARCH}"; then
    echo "[+] No prebuild cosign binary for ${OS}-${ARCH}."
    echo -e "[+] supported ones: ${supported}"
    exit 1
  fi

  if ! type "curl" >/dev/null && ! type "wget" >/dev/null; then
    echo "[+] Either curl or wget is required"
    exit 1
  fi
}

# initArch discovers the architecture for this system.
initArch() {
  ARCH=$(uname -m)
  case $ARCH in
  armv5*) ARCH="armv5" ;;
  armv6*) ARCH="armv6" ;;
  armv7*) ARCH="armv7" ;;
  aarch64) ARCH="arm64" ;;
  x86) ARCH="386" ;;
  x86_64) ARCH="amd64" ;;
  i686) ARCH="386" ;;
  i386) ARCH="386" ;;
  esac
}

# initOS discovers the operating system for this system.
initOS() {
  OS=$(uname | tr '[:upper:]' '[:lower:]')

  case "$OS" in
  # Msys support
  msys*) OS='windows' ;;
  # Minimalist GNU for Windows
  mingw*) OS='windows' ;;
  darwin) OS='darwin' ;;
  esac
}


# fail_trap is executed if an error occurs.
fail_trap() {
  result=$?
  if [ "$result" != "0" ]; then
    echo "[+] Failed to install cosign"
  fi
  echo "[+] cosign is installed succesfully"
  exit $result
}


download() {
echo "[+] https://storage.googleapis.com/cosign-releases/${COSIGN_VERSION}/cosign-${OS}-${ARCH} -o cosign"
curl -L https://storage.googleapis.com/cosign-releases/${COSIGN_VERSION}/cosign-${OS}-${ARCH} -o cosign
echo "[+] chmod +x ./cosign"
chmod +x ./cosign
echo "[+] curl -LO https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-${OS}-${ARCH}.sig"
curl -LO https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-${OS}-${ARCH}.sig
RELEASE_COSIGN_PUB_KEY=https://raw.githubusercontent.com/sigstore/cosign/${COSIGN_VERSION}/release/release-cosign.pub
echo "[+] ./cosign verify-blob --key $RELEASE_COSIGN_PUB_KEY --signature cosign-${OS}-${ARCH}.sig cosign"
./cosign verify-blob --key $RELEASE_COSIGN_PUB_KEY --signature cosign-${OS}-${ARCH}.sig cosign
if [[ $? != 0 ]]; then exit 1; fi
./cosign version
}

#Stop execution on any error
trap "fail_trap" EXIT
set -e
initArch
initOS
COSIGN_VERSION='v1.3.1'
echo "Downloading cosign for os: ${OS}, arch: ${ARCH} and version: ${COSIGN_VERSION}"
verifySupported
download
