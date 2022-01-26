############
# signing ci
############

.PHONY: sign-ci-containers
sign-ci-containers: ko
	cosign sign --yes --key .github/workflows/cosign-test.key -a GIT_HASH=$(GIT_HASH) ${KO_PREFIX}/cosign:$(GIT_HASH)
	cosign sign --yes --key .github/workflows/cosign-test.key -a GIT_HASH=$(GIT_HASH) ${KO_PREFIX}/sget:$(GIT_HASH)

.PHONY: sign-ci-keyless-containers
sign-ci-keyless-containers: ko
	./scripts/sign-images-ci.sh

.PHONY: sign-keyless-cosign
sign-keyless-cosign:
	cosign sign -a sha=$(GIT_HASH) -a run_id=${GITHUB_RUN_ID} -a run_attempt=${GITHUB_RUN_ATTEMPT} ${KO_PREFIX}/cosign:$(GIT_HASH)
	cosign sign -a sha=$(GIT_HASH) -a run_id=${GITHUB_RUN_ID} -a run_attempt=${GITHUB_RUN_ATTEMPT} ${KO_PREFIX}/cosign:$(GIT_VERSION)

.PHONY: sign-keyless-cosigned
sign-keyless-cosigned:
	cosign sign -a sha=$(GIT_HASH) -a run_id=${GITHUB_RUN_ID} -a run_attempt=${GITHUB_RUN_ATTEMPT} ${KO_PREFIX}/cosigned:$(GIT_HASH)
	cosign sign -a sha=$(GIT_HASH) -a run_id=${GITHUB_RUN_ID} -a run_attempt=${GITHUB_RUN_ATTEMPT} ${KO_PREFIX}/cosigned:$(GIT_VERSION)

.PHONY: sign-keyless-container
sign-keyless-container: ko sign-keyless-cosign sign-keyless-cosigned
