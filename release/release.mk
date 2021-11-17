##################
# release section
##################

# used when releasing together with GCP CloudBuild
.PHONY: release
release:
	LDFLAGS="$(LDFLAGS)" goreleaser release


###########################
# sign with GCP KMS section
###########################

.PHONY: sign-cosign-release
sign-cosign-release:
	cosign sign --force --key "gcpkms://projects/${PROJECT_ID}/locations/${KEY_LOCATION}/keyRings/${KEY_RING}/cryptoKeys/${KEY_NAME}/versions/${KEY_VERSION}" -a GIT_HASH=$(GIT_HASH) -a GIT_VERSION=$(GIT_VERSION) ${KO_PREFIX}/cosign:$(GIT_VERSION)

.PHONY: sign-cosigned-release
sign-cosigned-release:
	cosign sign --force --key "gcpkms://projects/${PROJECT_ID}/locations/${KEY_LOCATION}/keyRings/${KEY_RING}/cryptoKeys/${KEY_NAME}/versions/${KEY_VERSION}" -a GIT_HASH=$(GIT_HASH) -a GIT_VERSION=$(GIT_VERSION) ${KO_PREFIX}/cosigned:$(GIT_VERSION)

.PHONY: sign-sget-release
sign-sget-release:
	cosign sign --force --key "gcpkms://projects/${PROJECT_ID}/locations/${KEY_LOCATION}/keyRings/${KEY_RING}/cryptoKeys/${KEY_NAME}/versions/${KEY_VERSION}" -a GIT_HASH=$(GIT_HASH) -a GIT_VERSION=$(GIT_VERSION) ${KO_PREFIX}/sget:$(GIT_VERSION)

.PHONY: sign-container-release
sign-container-release: ko sign-cosign-release sign-cosigned-release sign-sget-release

######################
# sign keyless section
######################

.PHONY: sign-keyless-cosign-release
sign-keyless-cosign-release:
	cosign sign --force -a GIT_HASH=$(GIT_HASH) -a GIT_VERSION=$(GIT_VERSION) ${KO_PREFIX}/cosign:$(GIT_VERSION)

.PHONY: sign-keyless-cosigned-release
sign-keyless-cosigned-release:
	cosign sign --force -a GIT_HASH=$(GIT_HASH) -a GIT_VERSION=$(GIT_VERSION) ${KO_PREFIX}/cosigned:$(GIT_VERSION)

.PHONY: sign-keyless-sget-release
sign-keyless-sget-release:
	cosign sign --force -a GIT_HASH=$(GIT_HASH) -a GIT_VERSION=$(GIT_VERSION) ${KO_PREFIX}/sget:$(GIT_VERSION)

.PHONY: sign-keyless-release
sign-keyless-release: sign-keyless-cosign-release sign-keyless-cosigned-release sign-keyless-sget-release

# used when need to validate the goreleaser
.PHONY: snapshot
snapshot:
	LDFLAGS="$(LDFLAGS)" goreleaser release --skip-sign --skip-publish --snapshot --rm-dist
