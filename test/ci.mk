############
# signing ci
############

.PHONY: sign-ci-containers
sign-ci-containers: ko
	cosign sign --key .github/workflows/cosign-test.key -a GIT_HASH=$(GIT_HASH) ${KO_PREFIX}/cosign:$(GIT_HASH)
	cosign sign --key .github/workflows/cosign-test.key -a GIT_HASH=$(GIT_HASH) ${KO_PREFIX}/sget:$(GIT_HASH)

.PHONY: sign-ci-keyless-containers
sign-ci-keyless-containers: ko
	./scripts/sign-images-ci.sh

.PHONY: sign-blob-experimental
sign-blob-experimental:
	./test/sign_blob_test.sh
