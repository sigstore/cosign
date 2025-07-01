##################
# release section
##################
# used when releasing together with GCP CloudBuild
.PHONY: release
release:
	LDFLAGS="$(LDFLAGS)" goreleaser release --parallelism 1 --clean --timeout 120m

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
	LDFLAGS="$(LDFLAGS)" goreleaser release --skip=sign,publish --snapshot --clean --timeout 120m --parallelism 1

####################
# copy image to GHCR
####################

.PHONY: copy-signed-release-to-ghcr
copy-signed-release-to-ghcr:
	cosign copy $(KO_PREFIX)/cosign:$(GIT_VERSION) $(GHCR_PREFIX)/cosign:$(GIT_VERSION)
	cosign copy $(GHCR_PREFIX)/cosign:$(GIT_VERSION) $(GHCR_PREFIX)/cosign:latest
	cosign copy $(KO_PREFIX)/cosign:$(GIT_VERSION)-dev $(GHCR_PREFIX)/cosign:$(GIT_VERSION)-dev
	cosign copy $(GHCR_PREFIX)/cosign:$(GIT_VERSION)-dev $(GHCR_PREFIX)/cosign:latest-dev
