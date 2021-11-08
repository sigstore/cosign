##################
# release section
##################

# used when releasing together with GCP CloudBuild
.PHONY: release
release:
	LDFLAGS="$(LDFLAGS)" goreleaser release

.PHONY: sign-cosign-release
sign-cosign-release:
	cosign sign --key "gcpkms://projects/${PROJECT_ID}/locations/${KEY_LOCATION}/keyRings/${KEY_RING}/cryptoKeys/${KEY_NAME}/versions/${KEY_VERSION}" -a GIT_HASH=$(GIT_HASH) -a GIT_VERSION=$(GIT_VERSION) ${KO_PREFIX}/cosign:$(GIT_VERSION)

.PHONY: sign-cosigned-release
sign-cosigned-release:
	cosign sign --key "gcpkms://projects/${PROJECT_ID}/locations/${KEY_LOCATION}/keyRings/${KEY_RING}/cryptoKeys/${KEY_NAME}/versions/${KEY_VERSION}" -a GIT_HASH=$(GIT_HASH) -a GIT_VERSION=$(GIT_VERSION) ${KO_PREFIX}/cosigned:$(GIT_VERSION)

.PHONY: sign-sget-release
sign-sget-release:
	cosign sign --key "gcpkms://projects/${PROJECT_ID}/locations/${KEY_LOCATION}/keyRings/${KEY_RING}/cryptoKeys/${KEY_NAME}/versions/${KEY_VERSION}" -a GIT_HASH=$(GIT_HASH) -a GIT_VERSION=$(GIT_VERSION) ${KO_PREFIX}/sget:$(GIT_VERSION)

.PHONY: sign-container-release
sign-container-release: ko sign-cosign-release sign-cosigned-release sign-sget-release

# used when need to validate the goreleaser
.PHONY: snapshot
snapshot:
	LDFLAGS="$(LDFLAGS)" goreleaser release --skip-sign --skip-publish --snapshot --rm-dist
