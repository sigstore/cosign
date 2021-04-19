# Cutting a Sigstore Release
* Release notes: Create a PR to update and review release notes in CHANGELOG.md.
  - Check merged pull requests since the last release and make sure enhancements, bug fixes, and authors are reflected in the notes.
* Create the `v${VERSION}` tag and create a release
```
git tag -a v${VERSION}
```
* Upload binaries: After post-submit CI completes for the final PR, download binary artifacts from the “Cross” CI run. Unzip into an artifacts directory and upload to GCS:
```
gsutil cp -r artifacts gs://cosign-releases
```
* Tag the release container: Copy the container and signature uploaded by CI from `cosign/ci` to `cosign`

```
$ crane cp gcr.io/projectsigstore/cosign/ci/cosign:v${VERSION} gcr.io/projectsigstore/cosign:v${VERSION}
cosign triangulate gcr.io/projectsigstore/cosign/ci/cosign:v${VERSION}
$ crane cp gcr.io/projectsigstore/cosign/ci/cosign:sha256-${SHA_VERSION}.cosign gcr.io/projectsigstore/cosign:sha256-${SHA_VERSION}.cosign
```
* Tweet about the new release with a fun new trigonometry pun!

After the release:
* Add a pending new section in CHANGELOG.md to set up for the next release
