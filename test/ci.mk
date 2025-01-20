############
# signing ci
############

.PHONY: sign-ci-containers
sign-ci-containers: ko
	cosign sign --yes --key .github/workflows/cosign-test.key -a GIT_HASH=$(GIT_HASH) ${KO_PREFIX}/cosign:$(GIT_HASH)

.PHONY: sign-ci-keyless-containers
sign-ci-keyless-containers: ko
	./scripts/sign-images-ci.sh
