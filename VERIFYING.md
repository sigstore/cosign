# Verifying Cosign

The current (latest) release is used to sign itself.
The public key for each release is visible in the README.md and the KEYS.txt file of the repository,
at the commit of the release.
At each release we generate and sign the following blobs:
    COMMIT:TAG (the git commit and tag in a text file)
    cosign_platform_arch (for each platform and arch)
    cosign_platform_arch.sha256 (for each platform and arch)
These are pubished on GCS at: <foo> and in the GitHub release itself.

We also generate and sign the following containers:
    gcr.io/projectrekor/cosign (ko publish -f cmd/cli)
    gcr.io/projectrekor/cosign_action (ko publish -f cmd/action)

All artifacts and containers are signed with the following annotations:
* the clock time of the build system
* the git commit
* the github actions run url

Cosign releases are automated via GitHub actions.

The `cosign` secret key is stored in a `GCP Cloud Secret`.
It is accessed via a `GCP service account token` stored as a `GitHub` secret.
The password is  stored in a separate `GitHub` secret.

The secret key, token credentials and password are stored completely in memory.
They never hit disk.

All signatures are logged to `Rekor`, and signatures may be verified with `TLOG=1`.

These verifications can be done automatically with `cosign self-verify`.

# Verifying with `openssl`
<TODO>
