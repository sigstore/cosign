##################
# release section
##################
# used when releasing together with GCP CloudBuild
.PHONY: release
release:
	LDFLAGS="$(LDFLAGS)" goreleaser release --timeout 120m

######################
# sign section
######################

.PHONY: sign-release-images
sign-release-images: ko
	GIT_HASH=$(GIT_HASH) GIT_VERSION=$(GIT_VERSION) \
	./release/ko-sign-release-images.sh

# used when need to validate the goreleaser
.PHONY: snapshot
snapshot:
	LDFLAGS="$(LDFLAGS)" goreleaser release --skip-sign --skip-publish --snapshot --rm-dist --timeout 60m

####################
# copy image to GHCR
####################

.PHONY: copy-cosign-signed-release-to-ghcr
copy-cosign-signed-release-to-ghcr:
	cosign copy $(KO_PREFIX)/cosign:$(GIT_VERSION) $(GHCR_PREFIX)/cosign:$(GIT_VERSION)

.PHONY: copy-cosigned-signed-release-to-ghcr
copy-cosigned-signed-release-to-ghcr:
	cosign copy $(KO_PREFIX)/cosigned:$(GIT_VERSION) $(GHCR_PREFIX)/cosigned:$(GIT_VERSION)

.PHONY: copy-policy-webhook-signed-release-to-ghcr
copy-policy-webhook-signed-release-to-ghcr:
	cosign copy $(KO_PREFIX)/policy-webhook:$(GIT_VERSION) $(GHCR_PREFIX)/policy-webhook:$(GIT_VERSION)

.PHONY: copy-sget-signed-release-to-ghcr
copy-sget-signed-release-to-ghcr:
	cosign copy $(KO_PREFIX)/sget:$(GIT_VERSION) $(GHCR_PREFIX)/sget:$(GIT_VERSION)

.PHONY: copy-signed-release-to-ghcr
copy-signed-release-to-ghcr: copy-cosign-signed-release-to-ghcr copy-cosigned-signed-release-to-ghcr copy-sget-signed-release-to-ghcr copy-policy-webhook-signed-release-to-ghcr
