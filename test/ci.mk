############
# signing ci
############

.PHONY: sign-ci-containers
sign-ci-container: ko
	cosign sign --key .github/workflows/cosign-test.key -a GIT_HASH=$(GIT_HASH) ${KO_PREFIX}/cosign:$(GIT_HASH)
	cosign sign --key .github/workflows/cosign-test.key -a GIT_HASH=$(GIT_HASH) ${KO_PREFIX}/sget:$(GIT_HASH)

.PHONY: sign-ci-keyless-containers
sign-ci-keyless-container: ko
	cosign sign -a sha=$(GIT_HASH) -a run_id=${GITHUB_RUN_ID} -a run_attempt=${GITHUB_RUN_ATTEMPT} ${KO_PREFIX}/cosign:$(GIT_HASH)
	cosign sign -a sha=$(GIT_HASH) -a run_id=${GITHUB_RUN_ID} -a run_attempt=${GITHUB_RUN_ATTEMPT} ${KO_PREFIX}/cosign:$(GIT_VERSION)
	cosign sign -a sha=$(GIT_HASH) -a run_id=${GITHUB_RUN_ID} -a run_attempt=${GITHUB_RUN_ATTEMPT} ${KO_PREFIX}/sget:$(GIT_HASH)
	cosign sign -a sha=$(GIT_HASH) -a run_id=${GITHUB_RUN_ID} -a run_attempt=${GITHUB_RUN_ATTEMPT} ${KO_PREFIX}/sget:$(GIT_VERSION)

.PHONY: sign-blob-experimental
sign-blob-experimental:
	./test/sign_blob_test.sh
