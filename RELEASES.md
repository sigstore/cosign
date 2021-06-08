# Cutting a Sigstore Release
* Release notes: Create a PR to update and review release notes in CHANGELOG.md.
  - Check merged pull requests since the last release and make sure enhancements, bug fixes, and authors are reflected in the notes.
* Create a git tag for `${RELEASE_VER}` 
```shell
git checkout ... # The branch or commit to tag

export RELEASE_VER="v1.2.3"
git tag -a ${RELEASE_VER}
git push upstream/main $RELEASE_VER
```
* Create a release on GitHub for $RELEASE_VER
* Upload binaries: After post-submit CI completes for the final PR, download binary artifacts from the “Cross” CI run. Unzip into an artifacts directory and upload to GCS:
```shell
gsutil cp -r artifacts gs://cosign-releases
```
* Tag the release container: Copy the container and signature uploaded by CI from `cosign/ci` to `cosign`

```shell
crane cp gcr.io/projectsigstore/cosign/ci/cosign:${RELEASE_VER} gcr.io/projectsigstore/cosign:${RELEASE_VER}
export VERSION_SHA = $(crane digest gcr.io/projectsigstore/cosign:${RELEASE_VER} | sed s/sha256://g)
crane cp gcr.io/projectsigstore/cosign/ci/cosign:sha256-${VERSION_SHA}.sig gcr.io/projectsigstore/cosign:sha256-${VERSION_SHA}.sig
```
* Tweet about the new release with a fun new trigonometry pun!

After the release:
* Add a pending new section in CHANGELOG.md to set up for the next release
