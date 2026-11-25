# Release

This directory contain the files and scripts to run a cosign release.

# Cutting a Cosign Release

These steps cut a release from `main`. To cut a patch release from a release branch
(for example `release-3.1`), see [Cutting a patch release from a release branch](#cutting-a-patch-release-from-a-release-branch).

1. Release notes: Create a PR to update and review release notes in CHANGELOG.md.

Check merged pull requests since the last release and make sure enhancements, bug fixes, and authors are reflected in the notes.

You can get a list of pull requests since the last release by substituting in the date of the last release and running:

```
git log --pretty="* %s" --after="YYYY-MM-DD"
```

and a list of authors by running:

```
git log --pretty="* %an" --after="YYYY-MM-DD" | sort -u
```

2. Open a Pull Request to update CHANGELOG.md

3. Tag the repository

**WARNING**: Tags should not be updated to a new ref or deleted/recreated after creation. Go provides a [checksum database](https://sum.golang.org/)
that persists an immutable mapping between version and ref, and updating the tag will break clients that have already downloaded the release.

```shell
$ export RELEASE_TAG=<release version, eg "v2.0.2">
$ git fetch upstream
$ git tag -s ${RELEASE_TAG} -m "${RELEASE_TAG}" upstream/main
$ git push upstream ${RELEASE_TAG}
```

Note that `upstream` should be the upstream `sigstore/cosign` repository. You may have to change this if you've configured remotes.

The last argument to `git tag` is the commit to tag. Without it, `git tag` tags whatever you have checked out,
so check it before pushing:

```shell
$ git rev-parse ${RELEASE_TAG}^{commit}
```

4. Then go to the `Actions` tab and click on the [Cut Release workflow](https://github.com/sigstore/cosign/actions/workflows/cut-release.yml). The workflow
calls the shared [reusable release workflow](https://github.com/sigstore/community/blob/main/.github/workflows/reusable-release.yml) in `sigstore/community`,
and you need permission to run workflows in `sigstore/cosign` to trigger it.

Click to run a workflow on the `main` branch and insert the following parameters:

  - `Release tag`: the tag that you pushed for the release
  - `Key ring for cosign key`: the value is `release-cosign`
  - `Key name for cosign key`: the value is `cosign`

Or run it with the GitHub CLI:

```shell
$ gh workflow run cut-release.yml -R sigstore/cosign --ref main \
    -f release_tag=${RELEASE_TAG} -f key_ring=release-cosign -f key_name=cosign
```

That will trigger a CloudBuild job and will run the release using `goreleaser`, which will publish images to
`gcr.io` and `ghcr.io`, and the binaries will be available in the GitHub release.

The CloudBuild job reads `release/cloudbuild.yaml` from the branch the workflow runs on (`main`), and builds the
source checked out at the release tag.

If you have permissions to access the project, you can follow the CloudBuild job in the [`projectsigstore`](https://console.cloud.google.com/cloud-build/builds?project=projectsigstore) GCP Project.
It takes about 40 minutes.

As the last step of the CloudBuild job, `goreleaser` will create a `draft release` in GitHub.

5. Navigate to the `Draft Release` in the Github repository. Click the `Publish Release` button to make the Release available.

You might want/need to add any extra notes/breaking changes notices, upgrade paths.

**WARNING**: Immutable releases are enabled for this repository. Once published, a release can't be changed. Don't create
a release by hand; always publish the draft that `goreleaser` creates. If the CloudBuild job fails, fix the cause and run
the Cut Release workflow again.

6. Post on the `#general` and `#cosign` Slack channels.

7. If it's a significant release, send an announcement email to sigstore-dev@googlegroups.com mailing list.

# Cutting a patch release from a release branch

Use this when `main` has changes that must not ship in a patch release (for example, breaking changes queued for the
next major version). Patch releases are cut from a `release-X.Y` branch, such as `release-3.1`.

1. Backport the fixes. Open PRs against the release branch, not `main`. Prefix the title with the branch, for example
`[release-3.1] bump sigstore/sigstore to v1.11.4`.

2. Fix the release tooling on `main`, if needed. The Cut Release workflow always runs from `main`, so
`release/cloudbuild.yaml` on `main` is the config used to build the release, even for a release branch tag.
If the builder image or another release step needs a change, make it on `main` before cutting the release.
The release branch's own `release/cloudbuild.yaml` isn't used.

Also make sure the release branch builds with the toolchain in `main`'s `release/cloudbuild.yaml`, since that is
the builder image the release uses.

3. Tag the release branch, not `main`. You don't need to check out the branch; pass it to `git tag`:

```shell
$ export RELEASE_TAG=<release version, eg "v3.1.5">
$ export RELEASE_BRANCH=<release branch, eg "release-3.1">
$ git fetch upstream ${RELEASE_BRANCH}
$ git tag -s ${RELEASE_TAG} -m "${RELEASE_TAG}" upstream/${RELEASE_BRANCH}
$ git rev-parse ${RELEASE_TAG}^{commit}   # should be the head of the release branch
$ git push upstream ${RELEASE_TAG}
```

The warning in step 3 above applies here too: don't move or recreate the tag after you push it.

4. Run the Cut Release workflow on `main` with the new tag, as in step 4 above (`--ref main`, not the release branch).

5. Publish the draft release, as in step 5 above. Add the release notes to the draft before publishing.

6. Announce the release, as in steps 6 and 7 above.
