############
# signing ci
############

.PHONY: sign-container
sign-container: ko
	cosign sign --key .github/workflows/cosign-test.key -a GIT_HASH=$(GIT_HASH) ${KO_PREFIX}/cosign:$(GIT_HASH)

.PHONY: sign-policy-controller
sign-policy-controller:
	cosign sign --key .github/workflows/cosign-test.key -a GIT_HASH=$(GIT_HASH) ${KO_PREFIX}/policy-controller:$(GIT_HASH)

.PHONY: sign-sget
sign-sget:
	cosign sign --key .github/workflows/cosign-test.key -a GIT_HASH=$(GIT_HASH) ${KO_PREFIX}/sget:$(GIT_HASH)

.PHONY: sign-keyless-cosign
sign-keyless-cosign:
	cosign sign -a sha=$(GIT_HASH) -a run_id=${GITHUB_RUN_ID} -a run_attempt=${GITHUB_RUN_ATTEMPT} ${KO_PREFIX}/cosign:$(GIT_HASH)
	cosign sign -a sha=$(GIT_HASH) -a run_id=${GITHUB_RUN_ID} -a run_attempt=${GITHUB_RUN_ATTEMPT} ${KO_PREFIX}/cosign:$(GIT_VERSION)

.PHONY: sign-keyless-policy-controller
sign-keyless-policy-controller:
	cosign sign -a sha=$(GIT_HASH) -a run_id=${GITHUB_RUN_ID} -a run_attempt=${GITHUB_RUN_ATTEMPT} ${KO_PREFIX}/policy-controller:$(GIT_HASH)
	cosign sign -a sha=$(GIT_HASH) -a run_id=${GITHUB_RUN_ID} -a run_attempt=${GITHUB_RUN_ATTEMPT} ${KO_PREFIX}/policy-controller:$(GIT_VERSION)

.PHONY: sign-keyless-sget
sign-keyless-sget:
	cosign sign -a sha=$(GIT_HASH) -a run_id=${GITHUB_RUN_ID} -a run_attempt=${GITHUB_RUN_ATTEMPT} ${KO_PREFIX}/sget:$(GIT_HASH)
	cosign sign -a sha=$(GIT_HASH) -a run_id=${GITHUB_RUN_ID} -a run_attempt=${GITHUB_RUN_ATTEMPT} ${KO_PREFIX}/sget:$(GIT_VERSION)

.PHONY: sign-keyless-container
sign-keyless-container: ko sign-keyless-cosign sign-keyless-policy-controller sign-keyless-sget

.PHONY: sign-blob-experimental
sign-blob-experimental:
	./test/sign_blob_test.sh
