# Release

This directory contain the files and scripts to run a cosign release.

# Cutting a Sigstore Release

1. Release notes: Create a PR to update and review release notes in CHANGELOG.md.
  - Check merged pull requests since the last release and make sure enhancements, bug fixes, and authors are reflected in the notes.

You can get a list of pull requests since the last release by substituting in the date of the last release and running:

```
git log --pretty="* %s" --after="YYYY-MM-DD"
```

and a list of authors by running:

```
git log --pretty="* %an" --after="YYYY-MM-DD" | sort -u
```

2. Tag the repository

```shell
$ export RELEASE_TAG=<release version, eg "v1.4.0">
$ git tag -s ${RELEASE_TAG} -m "${RELEASE_TAG}"
$ git push origin ${RELEASE_TAG}
```


2. Submit the cloudbuild Job using the following command:

```shell
$ gcloud builds submit --config <PATH_TO_CLOUDBUILD> \
   --substitutions _GIT_TAG=${RELEASE_TAG},_TOOL_ORG=sigstore,_TOOL_REPO=cosign,_STORAGE_LOCATION=cosign-releases,_KEY_RING=<KEY_RING>,_KEY_NAME=<KEY_NAME> \
   --project <GCP_PROJECT>
```

Where:

- `PATH_TO_CLOUDBUILD` is the path where the cloudbuild.yaml can be found.
- `GCP_PROJECT` is the GCP project where we will run the job.
- `_GIT_TAG` is the release version we are publishing.
- `_TOOL_ORG` is the GitHub Org we will use. Default `sigstore`.
- `_TOOL_REPO` is the repository we will use to clone. Default `cosign`.
- `_STORAGE_LOCATION` where to push the built artifacts. Default `cosign-releases`.
- `_KEY_RING` key ring name of your cosign key.
- `_KEY_NAME` key name of your  cosign key.
- `_KEY_VERSION` version of the key stored in KMS. Default `1`.
- `_KEY_LOCATION` location in GCP where the key is stored. Default `global`.


3. When the job finish, whithout issues, you should be able to see in GitHub a draft release.
You now can review the release, make any changes if needed and then publish to make it an official release.

4. Send an announcement email to `sigstore-dev@googlegroups.com` mailing list

5. Tweet about the new release with a fun new trigonometry pun!

6. Honk!

#### After the release:

* Add a pending new section in CHANGELOG.md to set up for the next release
