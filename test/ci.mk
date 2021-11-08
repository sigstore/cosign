############
# signing ci
############

.PHONY: sign-container
sign-container: ko
	cosign sign --key .github/workflows/cosign.key -a GIT_HASH=$(GIT_HASH) ${KO_PREFIX}/cosign:$(GIT_HASH)

.PHONY: sign-cosigned
sign-cosigned:
	cosign sign --key .github/workflows/cosign.key -a GIT_HASH=$(GIT_HASH) ${KO_PREFIX}/cosigned:$(GIT_HASH)

.PHONY: sign-sget
sign-sget:
	cosign sign --key .github/workflows/cosign.key -a GIT_HASH=$(GIT_HASH) ${KO_PREFIX}/sget:$(GIT_HASH)
