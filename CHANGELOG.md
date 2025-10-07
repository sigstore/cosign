# v3.0.1

v3.0.1 is an equivalent release to v3.0.0, which was never published due to a failure in our CI workflows.

* Note that the `--bundle` flag specifying an output file to write the Sigstore bundle (which contains all relevant verification material) has moved from optional to required in v3.

## Changes

* update goreleaser config for v3.0.0 release (#4446)

# v3.0.0

Announcing the next major release of Cosign!

Cosign v3 is a minor change from Cosign v2.6.x, with all of the new capabilities of recent
releases **on by default**, but will still allow you to disable them if you need the older functionality.
These new features include support for the standardized bundle format (`--new-bundle-fomat`), providing roots
of trust for verification and service URLs for signing via one file (`--trusted-root`, `--signing-config`),
and container signatures stored as an OCI Image 1.1 referring artifact.

Learn more on our [v3 announcement blog post](https://blog.sigstore.dev/cosign-3-0-available/)! See
the changelogs for [v2.6.0](#v260), [v2.5.0](#v250), and [v2.4.0](#v240) for more information on recent
changes.

If you have any feedback, please reach out on Slack or file an issue on GitHub.

## Changes

* Default to using the new protobuf format (#4318)
* Fetch service URLs from the TUF PGI signing config by default (#4428)
* Bump module version to v3 for Cosign v3.0 (#4427)

# v2.6.1

## Bug Fixes

* Partially populate the output of cosign verify when working with new bundles (#4416)
* Bump sigstore-go, move conformance back to tagged release (#4426)

# v2.6.0

v2.6.0 introduces a number of new features, including:

* Signing an in-toto statement rather than Cosign constructing one from a predicate, along with verifying a statement's subject using a digest and digest algorithm rather than providing a file reference (#4306)
* Uploading a signature and its verification material (a ["bundle"](https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_bundle.proto)) as an OCI Image 1.1 referring artifact, completing [#3927](https://github.com/sigstore/cosign/issues/3927) (#4316)
* Providing service URLs for signing and attesting using a [SigningConfig](https://github.com/sigstore/protobuf-specs/blob/4df5baadcdb582a70c2bc032e042c0a218eb3841/protos/sigstore_trustroot.proto#L185). Note that this is required when using a [Rekor v2](https://github.com/sigstore/rekor-tiles) instance (#4319)

Example generation and verification of a signed in-toto statement:

```
cosign attest-blob --new-bundle-format=true --bundle="digest-key-test.sigstore.json" --key="cosign.key" --statement="../sigstore-go/examples/sigstore-go-signing/intoto.txt"
cosign verify-blob-attestation --bundle="digest-key-test.sigstore.json" --key=cosign.pub --type=unused --digest="b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9" --digestAlg="sha256"
```

Example container signing and verification using the new bundle format and referring artifacts:

```
cosign sign --new-bundle-format=true ghcr.io/user/alpine@sha256:a19367999603840546b8612572e338ec076c6d1f2fec61760a9e11410f546733
cosign verify --new-bundle-format=true ghcr.io/user/alpine@sha256:a19367999603840546b8612572e338ec076c6d1f2fec61760a9e11410f546733
```

Example usage of a signing config provided by the public good instance's TUF repository:

```
cosign sign-blob --use-signing-config --bundle sigstore.json README.md
cosign verify-blob --new-bundle-format --bundle sigstore.json --certificate-identity $EMAIL --certificate-oidc-issuer $ISSUER --use-signed-timestamps README.md
```

v2.6.0 leverages sigstore-go's signing and verification APIs gated behind these new flags. In an upcoming major release, we will be
updating Cosign to default to producing and consuming bundles to align with all other Sigstore SDKs.

## Features

* Add to `attest-blob` the ability to supply a complete in-toto statement, and add to `verify-blob-attestation` the ability to verify with just a digest (#4306)
* Have cosign sign support bundle format (#4316)
* Add support for SigningConfig for sign-blob/attest-blob, support Rekor v2 (#4319)
* Add support for SigningConfig in sign/attest (#4371)
* Support self-managed keys when signing with sigstore-go (#4368)
* Don't require timestamps when verifying with a key (#4337)
* Don't load content from TUF if trusted root path is specified (#4347)
* Add a terminal spinner while signing with sigstore-go (#4402)
* Require exclusively a SigningConfig or service URLs when signing (#4403)
* Remove SHA256 assumption in sign-blob/verify-blob (#4050)
* Bump sigstore-go, support alternative hash algorithms with keys (#4386)

## Breaking API Changes

* `sign.SignerFromKeyOpts` no longer generates a key. Instead, it returns whether or not the client needs to generate a key, and if so, clients
should call `sign.KeylessSigner`. This allows clients to more easily manage key generation.

## Bug Fixes

* Verify subject with bundle only when checking claims (#4320)
* Fixes to cosign sign / verify for the new bundle format (#4346)

# v2.5.3

## Features

* Add signing-config create command (#4280)
* Allow multiple services to be specified for trusted-root create (#4285)
* feat: Add OCI 1.1+ experimental support to tree (#4205)
* Add validity period end for trusted-root create (#4271)

## Bug Fixes

* Fix cert verification logic for trusted-root/SCTs (#4294)
* force when copying the latest image to overwrite (#4298)
* avoid double-loading trustedroot from file (#4264)

# v2.5.2

## Bug Fixes

* Do not load trusted root when CT env key is set

## Documentation

* docs: improve doc for --no-upload option (#4206)

# v2.5.1

## Features

* Add Rekor v2 support for trusted-root create (#4242)
* Add baseUrl and Uri to trusted-root create command
* Upgrade to TUF v2 client with trusted root
* Don't verify SCT for a private PKI cert (#4225)
* Bump TSA library to relax EKU chain validation rules (#4219)

## Bug Fixes

* Bump sigstore-go to pick up log index=0 fix (#4162)
* remove unused recursive flag on attest command (#4187)

## Docs

* Fix indentation in `verify-blob` cmd examples (#4160)

## Releases

* ensure we copy the latest tags on each release (#4157)

## Contributors

* arthurus-rex
* Babak K. Shandiz
* Bob Callaway
* Carlos Tadeu Panato Junior
* Colleen Murphy
* Dmitry Savintsev
* Emmanuel Ferdman
* Hayden B
* Ville Skyttä

# v2.5.0

v2.5.0 includes an implementation of the new bundle specification,
attesting and verifying OCI image attestations uploaded as OCI artifacts.
This feature is currently gated behind the `--new-bundle-format` flag
when running `cosign attest`.

## Features

* Add support for new bundle specification for attesting/verifying OCI image attestations (#3889)
* Feat/non filename completions (#4115)
* Add TSA certificate related flags and fields for cosign attest (#4079)

## Fixes

* cmd/cosign/cli: fix typo in ignoreTLogMessage (#4111)
* Fix replace with compliant image mediatype (#4077)

## Contributors

* Bob Callaway
* Carlos Tadeu Panato Junior
* Cody Soyland
* Dmitry Savintsev
* Hayden B
* Ramon Petgrave
* Riccardo Schirone
* Stef Graces
* Ville Skyttä

# v2.4.3

## Features

* Bump sigstore/sigstore to support KMS plugins (#4073)
* Enable fetching signatures without remote get. (#4047)
* Feat/file flag completion improvements (#4028)
* Update builder to use go1.23.6 (#4052)

## Bug Fixes

* fix parsing error in --only for cosign copy (#4049)

## Cleanup

* Refactor verifyNewBundle into library function (#4013)
* fix comment typo and imports order (#4061)
* sync comment with parameter name in function signature (#4063)
* sort properly Go imports (#4071)

## Contributors

* Bob Callaway
* Carlos Tadeu Panato Junior
* Cody Soyland
* Dmitry Savintsev
* Hayden B
* Tomasz Janiszewski
* Ville Skyttä

# v2.4.2

## Features

* Updated open-policy-agent to 1.1.0 library (#4036)
  - Note that only Rego v0 policies are supported at this time
* Add UseSignedTimestamps to CheckOpts, refactor TSA options (#4006)
* Add support for verifying root checksum in cosign initialize (#3953)
* Detect if user supplied a valid protobuf bundle (#3931)
* Add a log message if user doesn't provide `--trusted-root` (#3933)
* Support mTLS towards container registry (#3922)
* Add bundle create helper command (#3901)
* Add trusted-root create helper command (#3876)

## Bug Fixes

* fix: set tls config while retaining other fields from default http transport (#4007)
* policy fuzzer: ignore known panics (#3993)
* Fix for multiple WithRemote options (#3982)
* Add nightly conformance test workflow (#3979)
* Fix copy --only for signatures + update/align docs (#3904)

## Documentation

* Remove usage.md from spec, point to client spec (#3918)
* move reference from gcr to ghcr (#3897)

## Contributors

* AdamKorcz
* Aditya Sirish
* Bob Callaway
* Carlos Tadeu Panato Junior
* Cody Soyland
* Colleen Murphy
* Hayden B
* Jussi Kukkonen
* Marco Franssen
* Nianyu Shen
* Slavek Kabrda
* Søren Juul
* Warren Hodgkinson
* Zach Steindler

# v2.4.1

v2.4.1 largely contains bug fixes and updates dependencies.

## Features

* Added fuzzing coverage to multiple packages

## Bug Fixes
* Fix bug in attest-blob when using a timestamp authority with new bundles (#3877)
* fix: documentation link for installation guide (#3884)

## Contributors

* AdamKorcz
* Bob Callaway
* Carlos Tadeu Panato Junior
* Hayden B
* Hemil K
* Sota Sugiura
* Zach Steindler

# v2.4.0

v2.4.0 begins the modernization of the Cosign client, which includes:

* Support for the newer Sigstore specification-compliant bundle format
* Support for providing trust roots (e.g. Fulcio certificates, Rekor keys)
  through a trust root file, instead of many different flags
* Conformance test suite integration to verify signing and verification behavior

In future updates, we'll include:

* General support for the trust root file, instead of only when using the bundle
  format during verification
* Simplification of trust root flags and deprecation of the
  Cosign-specific bundle format
* Bundle support with container signing

We have also moved nightly Cosign container builds to GHCR instead of GCR.

## Features

* Add new bundle support to `verify-blob` and `verify-blob-attestation` (#3796)
* Adding protobuf bundle support to sign-blob and attest-blob (#3752)
* Bump sigstore/sigstore to support `email_verified` as string or boolean (#3819)
* Conformance testing for cosign (#3806)
* move incremental builds per commit to GHCR instead of GCR (#3808)
* Add support for recording creation timestamp for cosign attest (#3797)
* Include SCT verification failure details in error message (#3799)

## Contributors

* Bob Callaway
* Hayden B
* Slavek Kabrda
* Zach Steindler
* Zsolt Horvath

# v2.3.0

## Features

* Add PayloadProvider interface to decouple AttestationToPayloadJSON from oci.Signature interface (#3693)
* add registry options to cosign save (#3645)
* Add debug providers command. (#3728)
* Make config layers in ociremote mountable (#3741)
* upgrade to go1.22 (#3739)
* adds tsa cert chain check for env var or tuf targets. (#3600)
* add --ca-roots and --ca-intermediates flags to 'cosign verify' (#3464)
* add handling of keyless verification for all verify commands (#3761)

## Bug Fixes

* fix: close attestationFile (#3679)
* Set `bundleVerified` to true after Rekor verification (Resolves #3740)  (#3745)

## Documentation

* Document ImportKeyPair and LoadPrivateKey functions in pkg/cosign (#3776)

## Testing

* Refactor KMS E2E tests (#3684)
* Remove sign\_blob\_test.sh test (#3707)
* Remove KMS E2E test script (#3702)
* Refactor insecure registry E2E tests (#3701)

## Contributors

* Billy Lynch
* bminahan73
* Bob Callaway
* Carlos Tadeu Panato Junior
* Cody Soyland
* Colleen Murphy
* Dmitry Savintsev
* guangwu
* Hayden B
* Hector Fernandez
* ian hundere
* Jason Power
* Jon Johnson
* Max Lambrecht
* Meeki1l

# v2.2.4

## Bug Fixes

* Fixes for GHSA-88jx-383q-w4qc and GHSA-95pr-fxf5-86gv (#3661)
* ErrNoSignaturesFound should be used when there is no signature attached to an image. (#3526)
* fix semgrep issues for dgryski.semgrep-go ruleset (#3541)
* Honor creation timestamp for signatures again (#3549)

## Features

* Adds Support for Fulcio Client Credentials Flow, and Argument to Set Flow Explicitly (#3578)

## Documentation

* add oci bundle spec (#3622)
* Correct help text of triangulate cmd (#3551)
* Correct help text of verify-attestation policy argument (#3527)
* feat: add OVHcloud MPR registry tested with cosign (#3639)

## Testing

* Refactor e2e-tests.yml workflow (#3627)
* Clean up and clarify e2e scripts (#3628)
* Don't ignore transparency log in tests if possible (#3528)
* Make E2E tests hermetic (#3499)
* add e2e test for pkcs11 token signing (#3495)

# v2.2.3

## Bug Fixes

* Fix race condition on verification with multiple signatures attached to image (#3486)
* fix(clean): Fix clean cmd for private registries (#3446)
* Fixed BYO PKI verification (#3427)

## Features

* Allow for option in cosign attest and attest-blob to upload attestation as supported in Rekor (#3466)
* Add support for OpenVEX predicate type (#3405)

## Documentation

* Resolves #3088: `version` sub-command expected behaviour documentation and testing (#3447)
* add examples for cosign attach signature cmd (#3468)

## Misc

* Remove CertSubject function (#3467)
* Use local rekor and fulcio instances in e2e tests (#3478)

## Contributors

* aalsabag
* Bob Callaway
* Carlos Tadeu Panato Junior
* Colleen Murphy
* Hayden B
* Mukuls77
* Omri Bornstein
* Puerco
* vivek kumar sahu

# v2.2.2

v2.2.2 adds a new container with a shell, `gcr.io/projectsigstore/cosign:vx.y.z-dev`, in addition to the existing
container `gcr.io/projectsigstore/cosign:vx.y.z` without a shell.

For private deployments, we have also added an alias for `--insecure-skip-log`, `--private-infrastructure`.

## Bug Fixes

* chore(deps): bump github.com/sigstore/sigstore from 1.7.5 to 1.7.6 (#3411) which fixes a bug with using Azure KMS
* Don't require CT log keys if using a key/sk (#3415)
* Fix copy without any flag set (#3409)
* Update cosign generate cmd to not include newline (#3393)
* Fix idempotency error with signing (#3371)

## Features

* Add `--yes` flag `cosign import-key-pair` to skip the overwrite confirmation. (#3383)
* Use the timeout flag value in verify* commands. (#3391)
* add --private-infrastructure flag (#3369)

## Container Updates

* Bump builder image to use go1.21.4 and add new cosign image tags with shell  (#3373)

## Documentation

* Update SBOM\_SPEC.md (#3358)

## Contributors

* Carlos Tadeu Panato Junior
* Dylan Richardson
* Hayden B
* Lily Sturmann
* Nikos Fotiou
* Yonghe Zhao

# v2.2.1
**Note: This release comes with a fix for CVE-2023-46737 described in this [Github Security Advisory](https://github.com/sigstore/cosign/security/advisories/GHSA-vfp6-jrw2-99g9). Please upgrade to this release ASAP**

## Enhancements
* feat: Support basic auth and bearer auth login to registry (#3310)
* add support for ignoring certificates with pkcs11 (#3334)
* Support ReplaceOp in Signatures (#3315)
* feat: added ability to get image digest back via triangulate (#3255)
* feat: add `--only` flag in `cosign copy` to copy sign, att & sbom (#3247)
* feat: add support attaching a Rekor bundle to a container (#3246)
* feat: add support outputting rekor response on signing (#3248)
* feat: improve dockerfile verify subcommand (#3264)
* Add guard flag for experimental OCI 1.1 verify. (#3272)
* Deprecate SBOM attachments (#3256)
* feat: dedent line in cosign copy doc (#3244)
* feat: add platform flag to cosign copy command (#3234)
* Add SLSA 1.0 attestation support to cosign. Closes #2860 (#3219)
* attest: pass OCI remote opts to att resolver. (#3225)

## Bug Fixes
* Merge pull request from GHSA-vfp6-jrw2-99g9
* fix: allow cosign download sbom when image is absent (#3245)
* ci: add a OCI registry test for referrers support (#3253)
* Fix ReplaceSignatures (#3292)
* Stop using deprecated in_toto.ProvenanceStatement (#3243)
* Fixes #3236, disable SCT checking for a cosign verification when usin… (#3237)
* fix: update error in `SignedEntity` to be more descriptive (#3233)
* Fail timestamp verification if no root is provided (#3224)


## Documentation
* Add some docs about verifying in an air-gapped environment (#3321)
* Update CONTRIBUTING.md (#3268)
* docs: improves the Contribution guidelines (#3257)
* Remove security policy (#3230)


## Others
* Set go to min 1.21 and update dependencies  (#3327)
* Update contact for code of conduct (#3266)
* Update .ko.yaml (#3240)


## Contributors
* AdamKorcz
* Andres Galante
* Appu
* Billy Lynch
* Bob Callaway
* Caleb Woodbine
* Carlos Tadeu Panato Junior
* Dylan Richardson
* Gareth Healy
* Hayden B
* John Kjell
* Jon Johnson
* jonvnadelberg
* Luiz Carvalho
* Priya Wadhwa
* Ramkumar Chinchani
* Tosone
* Ville Aikas
* Vishal Choudhary
* ziel

# v2.2.0

## Enhancements

* switch to uploading DSSE types to rekor instead of intoto (#3113)
* add 'cosign sign' command-line parameters for mTLS (#3052)
* improve error messages around bundle != payload hash (#3146)
* make VerifyImageAttestation function public (#3156)
* Switch to cryptoutils function for SANS (#3185)
* Handle HTTP_1_1_REQUIRED errors in github provider (#3172)

## Bug Fixes

* Fix nondeterminsitic timestamps (#3121)

## Documentation

* doc: Add example of sign-blob with key in env var (#3152)
* add deprecation notice for cosign-releases GCS bucket (#3148)
* update doc links (#3186)

## Others

* Upgrade to go1.21 (#3188)
* Updates ci tests (#3142)
* test using latest release of scaffolding (#3187)
* ci: free up disk space for the gh runner (#3169)
* update go-github to v53 (#3116)
* call e2e test for cosign attach  (#3112)
* bump build cross to use go1.20.6 and cosign image to 2.1.1 (#3108)

## Contributors

* Bob Callaway
* Carlos Tadeu Panato Junior
* Dmitry Savintsev
* Hayden B
* Hector Fernandez
* Jason Hall
* Jon Johnson
* Jubril Oyetunji
* Paulo Gomes
* Priya Wadhwa
* 张志强

# v2.1.1

## Bug Fixes
* wait for the workers become available again to continue the execution (#3084)
* fix help text when in a container (#3082)

## Documentation
* update changelog (#3080)
* DNM: Add CHANGELOG for v2.1.0 (#3068)

## Contributors

* Carlos Tadeu Panato Junior
* priyawadhwa

# v2.1.0

**Breaking Change: The predicate is now a required flag in the attest commands, set via the --type flag.**

## Enhancements
* Verify sigs and attestations in parallel (#3066)
* Deep inspect attestations when filtering download (#3031)
* refactor bundle validation code, add support for DSSE rekor type (#3016)
* Allow overriding remote options (#3049)
* feat: adds no cert found on sig exit code (#3038)
* Make predicate a required flag in attest commands (#3033)
* Added support for attaching Time stamp authority Response in attach command (#3001)
* Add `sign --sign-container-identity` CLI (#2984)
* Feature: Allow cosign to sign digests before they are uploaded. (#2959)
* accepts `attachment-tag-prefix` for `cosign copy` (#3014)
* Feature: adds '--allow-insecure-registry' for cosign load (#3000)
* download attestation: support --platform flag (#2980)
* Cleanup: Add `Digest` to the `SignedEntity` interface. (#2960)
* verify command: support keyless verification using only a provided certificate chain with non-fulcio roots (#2845)
* verify: use workers to limit the paralellism when verifying images with --max-workers flag (#3069)

## Bug Fixes
* Fix pkg/cosign/errors (#3050)
* fix: update doc to refer to github-actions oidc provider (#3040)
* fix: prefer GitHub OIDC provider if enabled (#3044)
* Fix --sig-only in cosign copy (#3074)

## Documentation
* Fix links to sigstore/docs in markdown files (#3064)
* Update release readme (#2942)

## Contributors

**Thank you to our contributors!**
* Bob Callaway
* Carlos Tadeu Panato Junior
* Chok Yip Lau
* Chris Burns
* Dmitry Savintsev
* Enyinna Ochulor
* Hayden B
* Hector Fernandez
* Jakub Hrozek
* Jason Hall
* Jon Johnson
* Luiz Carvalho
* Matt Moore
* Mritunjay Kumar Sharma
* Mukuls77
* Ramkumar Chinchani
* Sascha Grunert
* Yolanda Robla Mota
* priyawadhwa

# v2.0.2

## Enhancements

* Update sigstore/sigstore to v1.6.2 to pick up TUF CDN change (#2891)
* feat: Make cosign copy faster (#2901)
* remove sget (#2885)
* Require a payload to be provided with a signature (#2785)

## Bug Fixes

* cmd: Change error message from KeyParseError to PubKeyParseError for verify-blob. (#2876)
* Use `SOURCE_DATE_EPOCH` for OCI CreatedAt times (#2878)

## Documentation

* Remove experimental warning from Fulcio flags (#2923)
* add missing oidc provider (#2922)
* Add zot as a supported registry (#2920)
* deprecates `kms_support` docs (#2900)
* chore(docs) deprecate note for usage docs (#2906)
* adds note of deprecation for examples.md docs (#2899)

## Contributors

* Carlos Tadeu Panato Junior
* Chris Burns
* Dmitry Savintsev
* eiffel-fl
* Hayden B
* Hector Fernandez
* Jon Johnson
* Miloslav Trmač
* priyawadhwa
* Ramkumar Chinchani

# v2.0.1

## Enhancements

* Add environment variable token provider (#2864)
* Remove cosign policy command (#2846)
* Allow customising 'go' executable with GOEXE var (#2841)
* Consistent tlog warnings during verification (#2840)
* Add riscv64 arch (#2821)
* Default generated PEM labels to SIGSTORE (#2735)
* Update privacy statement and confirmation (#2797)
* Add exit codes for verify errors (#2766)
* Add Buildkite provider (#2779)
* verify-blob-attestation: Loosen arg requirements if --check-claims=false (#2746)

## Bug Fixes

* PKCS11 sessions are now opened read only (#2853)
* Makefile: date format of log should not show signatures (#2835)
* Add missing flags to cosign verify dockerfile/manifest (#2830)
* Add a warning to remember how to configure a custom Gitlab host (#2816)
* Remove tag warning message from save/copy commands (#2799)
* Mark keyless pem files with b64 (#2671)

## Contributors

* Aleksandr Razumov
* Batuhan Apaydın
* Billy Lynch
* Carlos Tadeu Panato Junior
* Chris Burns
* Derek Burdick
* Dmitry Savintsev
* favonia
* Hayden B
* Hector Fernandez
* Ivana Atanasova
* joe miller
* Luiz Carvalho
* Paolo Mainardi
* priyawadhwa
* Radoslav Dimitrov
* Steve Winslow
* Vincent Batts
* Zack Newman

# v2.0.0
This is the official 2.0.0 release of cosign!
There are many new features and breaking changes from version 1.x, for a full explanation please read the Cosign 2.0 [blog post](https://blog.sigstore.dev/).

## Breaking Changes
* `COSIGN_EXPERIMENTAL=1` is no longer required to have identity-based ("keyless") signing and transparency.
* By default, artifact signatures will be uploaded to Rekor, for both key-based and identity-based signing. To not upload to Rekor, include `--tlog-upload=false`.
  * You must also include `--insecure-ignore-tlog=true` when verifying an artifact that was not uploaded to Rekor.
  * Examples of when you may want to skip uploading to the transparency log are if you have a private Sigstore deployment that does not use transparency or a private artifact.
  * We strongly encourage all other use-cases to upload artifact signatures to Rekor. Transparency is a critical component of supply chain security, to allow artifact maintainers and consumers to monitor a public log for their artifacts and signing identities.
* Verification now requires identity flags, `--certificate-identity` and `--certificate-oidc-issuer`. Like verifying a signature with a public key, it's critical to specify who you trust to generate a signature for identity-based signing. See sigstore/cosign#2056 for more discussion on this change.
* --certificate-email has been removed. Use --certificate-identity, which supports not only email verification but also any identity specified in a certificate, including SPIFFE, GitHub Actions, or service account identities.
* Cosign no longer supports providing a certificate that does not conform to the Fulcio certificate profile, which includes setting the SubjectAlternativeName and OIDC Issuer OID. To verify with a non-conformant certificate, extract the public key from the certificate and verify with `cosign verify --key <key.pem>`. We are actively working on more support for custom certificates for those who want to bring their existing PKI.
* Signing OCI images by tag prints a warning and is strongly discouraged, e.g. `cosign sign container.registry.io/foo:tag`. This is considered insecure since tags are mutable. If you want to specify a particular image, you are recommended to do so by digest.
* SCT verification, a proof of inclusion in a certificate transparency log, is now on by default for verifying Fulcio certificates. For private deployments without certificate transparency, use `--insecure-ignore-sct=true` to skip this check.
* DSSE support in verify-blob has been removed. You can now verify attestations using verify-blob-attestation.
* Environment variable `SIGSTORE_TRUST_REKOR_API_PUBLIC_KEY` has been removed. For private deployments, if you would like to set the Rekor public key to verify transparency log entries, use either a TUF setup or set `SIGSTORE_REKOR_PUBLIC_KEY` with the PEM of the custom Rekor public key..
* verify-blob no longer searches for a certificate. You must provide one with either `--certificate` or `--bundle`.
* `cosign attest --type {custom|vuln}` (and `cosign verify-attestation`) will now use the RFC 3986 compliant URIs, adding https://, so that these predicate types are compliant with the in-toto specification.
* The CosignPredicate envelope that wraps the predicates of SPDX and CycloneDX attestations has been removed, which was a violation of the schema specified via the predicateType field (more information).
* `--force` has been removed. To skip any prompts, use `--yes`.

## Improvements
* Blob attestation and verification is now supported with cosign attest-blob and cosign verify-blob-attestation.
* You can now set flags via environment variables, for example instead of `--certificate-identity=email`, you can set an environment variable for `COSIGN_CERTIFICATE_IDENTITY=email`.
* `--offline=true` removes the fallback to the Rekor log when verifying an artifact. Previously, if you did not provide a bundle (a persisted response from Rekor), Cosign would fallback to querying Rekor. You can now skip this fallback for offline environments. Note that if the bundle fails to verify, Cosign will not fallback and will fail early.
* A Fulcio certificate can now be issued for self-managed keys by providing `--issue-certificate=true` with a key, `--key`, or security key, `--sk`. This is useful when adopting Sigstore incrementally.
* Experimental support for trusted timestamping has been added. Timestamping leverages a third party to provide the timestamp that will be used to verify short-lived Fulcio certificates, which distributes trust. We will be writing more about this in an upcoming blog post!
  * To use a timestamp when signing a container, use` cosign sign --timestamp-server-url=<url> <container>`, such as https://freetsa.org/tsr, and to verify, `cosign verify --timestamp-certificate-chain=<path-to-PEM-encodeded-chain> <other flags> <artifact>`.
  * To use a timestamp when signing a blob, use `cosign sign-blob --timestamp-server-url=<url> --rfc3161-timestamp=<output-path> --bundle=<output-path> <blob>`, and to verify, `cosign verify-blob --rfc3161-timestamp=<output-path> --timestamp-certificate-chain=<path-to-PEM-encoded-chain> --bundle=<output-path> <other flags> <blob>`.

For specific PRs representing enhancements, bug fixes, documentation, and breaking changes, please see the sections below for prereleases v2.0.0-rc.0, v2.0.0-rc.1, v2.0.0-rc.2, and v2.0.0-rc.3.

### Thanks to all contributors!

* Anish Shah
* Arnaud J Le Hors
* Arthur Lutz
* Batuhan Apaydın
* Bob Callaway
* Carlos Tadeu Panato Junior
* Chris Burns
* Christian Loos
* Emmanuel T Odeke
* Hayden B
* Hector Fernandez
* Huang Huang
* Jan Wozniak
* Josh Dolitsky
* Josh Wolf
* Kenny Leung
* Marko Mudrinić
* Matt Moore
* Matthias Glastra
* Miloslav Trmač
* Mukuls77
* Priya Wadhwa
* Puerco
* Stefan Zhelyazkov
* Tim Seagren
* Tom Meadows
* Ville Aikas
* Zack Newman
* asraa
* kpk47
* priyawadhwa


# v2.0.0-rc.3
_Note: this is a prerelease for Cosign 2.0! Feel free to try it out, but know there are many breaking changes from 1.0 and the prereleases may continue to change._

## Enhancements
* Support non-Sigstore TSA requests (#2708)
* Add COSIGN_OCI_EXPERIMENTAL, push .sig/.sbom using OCI 1.1+ digest tag (#2684)
* Output certificate in bundle when entry is not uploaded to Rekor (#2715)
* attach signature and attach sbom must use STDIN to upload raw string (#2637)

## Bug Fixes
* Fix: Add missing schemes to cosign predicate types. (#2717)
* Fix: Drop the `CosignPredicate` wrapper around SBOM attestations. (#2718)

## Documentation
* Adds deprecation note for keyless docs (#2716)


# v2.0.0-rc.2
_Note: this is a prerelease for Cosign 2.0! Feel free to try it out, but know there are many breaking changes from 1.0 and the prereleases may continue to change._

## Enhancements
* add generate-key-pair GitHub Enterprise server support (#2676)
* add in format string for warning (#2699)
* Support for fetching Fulcio certs with self-managed key (#2532)
* 2476 predicate type download (#2484)
* Upgrade to go1.20 (#2689)

## Bug Fixes
* Fix prompts with Windows line endings (#2674)

## Documentation

* docs(README): verify example failing on latest (#2694)

## Contributors
* Anish Shah
* Arthur Lutz
* Carlos Tadeu Panato Junior
* Christian Loos
* Tim Seagren
* Zack Newman
* priyawadhwa

# v2.0.0-rc.1
_Note: this is a prerelease for Cosign 2.0! Feel free to try it out, but know there are many breaking changes from 1.0 and the prereleases may continue to change._

Critical breaking changes include:
* Certificate issuer and subject are now required on `cosign verify`

## Breaking Changes
* insecure-skip-tlog-verify: rename and adapt the cert expiration check (#2620)
* Deprecate --certificate-email flag. Make --certificate-identity and -… (#2411)

## Enhancements
* Add warning to use digest instead of tags to other cosign commands (#2650)
* Fix up UI messages (#2629)
* Remove hardcoded Fulcio from output (#2621)
* Fix missing privacy statement, print in multiple locations (#2622)
* feat: allows custom key names for import-key-pair (#2587)
* feat: support keyless verification for verify-blob-attestation (#2525)
* attest-blob: add functionality for keyless signing (#2515)
* Rego: add support for custom error/warning messages when evaluating rego rules (#2577)
* feat: add debug information to cert validation error (#2579)

## Bug Fixes
* fix: panic with unsigned local image (#2656)
* Make sure a cert passed in via --cert matches the bundle cert (#2652)
* fix: fix github oidc post submit test (#2594)
* fix: add enhanced error messages for failing verification with TUF targets (#2589)

## Contributors
* Carlos Tadeu Panato Junior
* Chris Burns
* Hayden B
* Hector Fernandez
* Huang Huang
* Kenny Leung
* Priya Wadhwa
* Stefan Zhelyazkov
* Ville Aikas
* Zack Newman
* asraa
* dependabot[bot]
* kpk47
* priyawadhwa

# v2.0.0-rc.0

_Note: this is a prerelease for Cosign 2.0! Feel free to try it out, but know there are many breaking changes from 1.0 and the prereleases may continue to change._

Critical breaking changes include:
* Removing the COSIGN_EXPERIMENTAL environment variable, so the default signing method is now keyless signing with Fulcio
* By default Cosign will now always upload to Rekor, this can be toggled with the `--tlog-upload` flag (defaults to true)

## Breaking Changes
* Breaking change: Change SCT verification behavior to default to enforcement (#2400)
* Breaking change: remove --force flag from sign and attest and rely on --yes flag to skip confirmation (#2399)
* Breaking change: replace --no-tlog-upload flag with --tlog-upload flag (#2397)

## Enhancements
* Change go module name to github.com/sigstore/cosign/v2 for Cosign 2.0 (#2544)
* Allow users to pass in a path for the --identity-token flag (#2538)
* Breaking change: Respect tlog-upload=false, default to true (#2505)
* Support outputing a certificate without uploading to the tlog (#2506)
* Attestation/Blob signing and verification using a RFC3161 time-stamping server (#2464)
* respect tlog-upload flag with TSA (#2474)
* Better feedback if specifying incompatible argument on `cosign sign --attachment` (#2449)
* Support TSA and Rekor verifications (#2463)
* add support for tsa signing and verification of images (#2460)
* cosign policy sign: remove experimental flag and make keyless signing default (#2459)
* Remove experimental mode from cosign attest and verify-attestation (#2458)
* Remove experimental mode from sign-blob and verify-blob (#2457)
* Add --offline flag to force offline verification (#2427)
* Air gap support (#2299)
* Remove experimental flag from cosign sign and cosign verify (#2387)
* verify: remove SIGSTORE_TRUST_REKOR_API_PUBLIC_KEY test env var for using a key from rekor's API  (#2362)

## Bug Fixes
* Fix the file existence check. (#2552)
* Fix timestamp verification, add verify-blob tests (#2527)
* fix(verify): Consolidate certificate expiry logic (#2504)
* Updates to Timestamp signing and verification (#2499)
* fix: removes attestation payload from attest-blob's output & no base64 encoding (#2498)
* Fix path for e2e-tests badge (#2490)
* Fix spdx json media type (#2479)
* fix sct verificaction (#2426)

## Others
* update builder image that uses go 1.19.4 (#2520)

## Contributors
* Anish Shah
* Arnaud J Le Hors
* Batuhan Apaydın
* Bob Callaway
* Carlos Tadeu Panato Junior
* Emmanuel T Odeke
* Hayden B
* Hector Fernandez
* Jan Wozniak
* Matthias Glastra
* Miloslav Trmač
* Puerco
* Tom Meadows
* Ville Aikas
* Zack Newman
* asraa
* priyawadhwa

# v1.13.6

_Note: v1.13.3, .4, and .5 were skipped due to issues in the release pipeline_

This release backports support for the latest TUF specification. We encourage users to upgrade to Cosign v2.

## Updates
* V1 go tuf update (#3598)
* Update cloud build script to latest for v1.13.x (#3615)

# v1.13.2

This release backports a security fix. We encourage users to upgrade to Cosign v2.

## Updates
* [release-1.13] update builder image that uses go 1.19.4 (#2521)
* Backport GHSA-vfp6-jrw2-99g9 in (#3364)

# v1.13.1

## Enhancements
* verify-blob-attestation: allow multiple subjects in in_toto attestation (#2341)
* Add verify-blob-attestation command and tests (#2337)
* Add --output-attestation flag to attest-blob and remove experimental signing (#2332)
* Add attest-blob command (#2286)
* Add '--cert-identity' flag to support subject alternate names for ver… (#2278)
* Update Dockerfile section of README (#2323)

## Bug Fixes
* Update warning when users sign images by tag. (#2313)

## Others
* Remove experimental flags from attest-blob and refactor (#2338)

## Contributors
* Alex Cameron
* Ville Aikas
* Zack Newman
* asraa
* kpk47
* priyawadhwa

# v1.13.0

> # Highlights
> * For users who have deployed a private instance of Fulcio release v0.6.x and issue certificates with the Username identity, you will need to upgrade to use this version."

## Enhancements

* Add support for Fulcio username identity in SAN (https://github.com/sigstore/cosign/pull/2291)
* Data race in FetchSignaturesForReference (https://github.com/sigstore/cosign/pull/2283)
* Check error on chain verification failure (https://github.com/sigstore/cosign/pull/2284)
* feat: improve the verification message (https://github.com/sigstore/cosign/pull/2268)
* feat: use stdin as an input for predicate (https://github.com/sigstore/cosign/pull/2269)

## Bug Fixes

* fix: make tlog entry lookups for online verification shard-aware (https://github.com/sigstore/cosign/pull/2297)
* Fix: Create a static copy of signatures as part of verification. (https://github.com/sigstore/cosign/pull/2287)
* Fix: Remove an extra registry request from verification path. (https://github.com/sigstore/cosign/pull/2285)
* fix pivtool generate key touch policy (https://github.com/sigstore/cosign/pull/2282)

## Others

* use scaffolding 0.4.8 for tests. (https://github.com/sigstore/cosign/pull/2280)

## Contributors

* Asra Ali (@asraa)
* Batuhan Apaydın (@developer-guy)
* Carlos Tadeu Panato Junior (@cpanato)
* Hayden Blauzvern (@haydentherapper)
* Matt Moore (@mattmoor)
* Ross Tannenbaum (@RTann)
* Ville Aikas (@vaikas)

# v1.12.1

> # Highlights
> * Pulls Fulcio root and intermediate when `--certificate-chain` is not passed into `verify-blob`. The v1.12.0 release introduced a regression: when `COSIGN_EXPERIMENTAL` was not set, cosign `verify-blob` would check a `--certificate` (without a `--certificate-chain` provided) against the operating system root CA bundle. In this release, Cosign checks the certificate against Fulcio's CA root instead (restoring the earlier behavior).

## Bug Fixes

* fix: fixing breaking changes in  rekor v1.12.0 upgrade (https://github.com/sigstore/cosign/pull/2260)
* Fixed bug where intermediate certificates were not automatically read from the OCI chain annotation (https://github.com/sigstore/cosign/pull/2244)
* fix: add COSIGN_EXPERIMENTAL=1 for verify-blob (https://github.com/sigstore/cosign/pull/2254)
* fix: fix cert chain validation for verify-blob in non-experimental mode (https://github.com/sigstore/cosign/pull/2256)
* fix: fix secret test, non-experimental bundle should pass (https://github.com/sigstore/cosign/pull/2249)
* Fix e2e test failure, add test for local bundle without rekor bundle (https://github.com/sigstore/cosign/pull/2248)

## Contributors

* Asra Ali (@asraa)
* Batuhan Apaydın (@developer-guy)
* Carlos Tadeu Panato Junior (@cpanato)
* Hayden Blauzvern (@haydentherapper)
* n3k0m4 (@n3k0m4)

# v1.12.0

**Note: This release comes with a fix for `CVE-2022-36056` described in this [Github Security Advisory](https://github.com/sigstore/cosign/security/advisories/GHSA-8gw7-4j42-w388). Please upgrade to this release ASAP**

> # Highlights
> **BREAKING:** The fix for [GHSA-GHSA-8gw7-4j42-w388](https://github.com/sigstore/cosign/security/advisories/GHSA-8gw7-4j42-w388) (CVE-2022-36056) means that some `verify-blob` commands that used to work may not anymore. In particular:
> - When using `verify-blob` with signatures created with keyless mode, we require either `COSIGN_EXPERIMENTAL=1` or a valid Rekor bundle for offline verification passed with `--bundle`.
>
> If you upgrade and encounter other issues, please read the advisory in full; your prior checks may have been passing inappropriately.


## Enhancements

* Add deprecation warning for sget CLI and packages (https://github.com/sigstore/cosign/pull/2019)
* feat: set annotations to generate additional bash completion information (https://github.com/sigstore/cosign/pull/2221)
* feat: integrate Alibaba Cloud Container Registry cred helper (https://github.com/sigstore/cosign/pull/2008)
* Support non-ECDSA key types for verify-blob (https://github.com/sigstore/cosign/pull/2203)
* Bump github.com/theupdateframework/go-tuf from 0.3.1 to 0.5.0 (https://github.com/sigstore/cosign/pull/2232)
    * feat: Add support for verifying ECDSA PEM-encoded keys. Continues deprecated hex-encoded keys for backward compatibility

## Bug Fixes

* fix: fix secret test, non-experimental bundle should pass (https://github.com/sigstore/cosign/pull/2249)
* Fix e2e test failure, add test for local bundle without rekor bundle (https://github.com/sigstore/cosign/pull/2248)
* Clarify error when KMS provider fails to load (https://github.com/sigstore/cosign/pull/2220)

## Others

* update kind to use release v0.15.0 and some version comments (https://github.com/sigstore/cosign/pull/2246)
* Bump github.com/theupdateframework/go-tuf from 0.3.1 to 0.5.0 (https://github.com/sigstore/cosign/pull/2232)
* update go builder to go1.19.1 (https://github.com/sigstore/cosign/pull/2241)
* Bump mikefarah/yq from 4.27.3 to 4.27.5 (https://github.com/sigstore/cosign/pull/2239)
* Bump github.com/open-policy-agent/opa from 0.43.0 to 0.44.0 (https://github.com/sigstore/cosign/pull/2234)
* Bump github.com/google/go-cmp from 0.5.8 to 0.5.9 (https://github.com/sigstore/cosign/pull/2233)
* Bump google.golang.org/api from 0.94.0 to 0.95.0 (https://github.com/sigstore/cosign/pull/2229)
* upgrade setup-ko to point to new repo (https://github.com/sigstore/cosign/pull/2225)
* Bump github.com/spf13/viper from 1.12.0 to 1.13.0 (https://github.com/sigstore/cosign/pull/2224)
* Upgrade to go1.19 (https://github.com/sigstore/cosign/pull/2213)
* remove doubl quotes, looks like it is passing as a single string to cosign and not as an array (https://github.com/sigstore/cosign/pull/2205)
* use scaffolding v0.4.6. (https://github.com/sigstore/cosign/pull/2201)
* Bump google.golang.org/api from 0.93.0 to 0.94.0 (https://github.com/sigstore/cosign/pull/2200)

## Contributors

* Asra Ali (@asraa)
* Carlos Tadeu Panato Junior (@cpanato)
* Engin Diri (@dirien)
* Hayden Blauzvern (@haydentherapper)
* Huang Huang (@mozillazg)
* Jason Hall (@imjasonh)
* Priya Wadhwa (@priyawadhwa)
* Ville Aikas (@vaikas)
* Zack Newman (@znewman01)

# v1.11.1

## Enhancements

* feat: Rework fig autocomplete command (https://github.com/sigstore/cosign/pull/2187)

## Bug Fixes

* fix: fix typo that caused attestation verification failure (https://github.com/sigstore/cosign/pull/2199)

## Documention

* add release cadence section in the readme (https://github.com/sigstore/cosign/pull/2179)

## Others

* Bump actions/cache from 3.0.7 to 3.0.8 (https://github.com/sigstore/cosign/pull/2192)
* Bump actions/dependency-review-action from 2.0.4 to 2.1.0 (https://github.com/sigstore/cosign/pull/2185)
* Bump actions/setup-go from 3.2.1 to 3.3.0 (https://github.com/sigstore/cosign/pull/2196)
* Bump github.com/go-openapi/swag from 0.22.1 to 0.22.3 (https://github.com/sigstore/cosign/pull/2182)
* Bump github.com/sigstore/fulcio from 0.5.2 to 0.5.3 (https://github.com/sigstore/cosign/pull/2190)
* Bump github.com/sigstore/rekor from 0.10.0 to 0.11.0 (https://github.com/sigstore/cosign/pull/2181)
* Bump github.com/xanzy/go-gitlab from 0.72.0 to 0.73.0 (https://github.com/sigstore/cosign/pull/2191)
* Bump github.com/xanzy/go-gitlab from 0.73.0 to 0.73.1 (https://github.com/sigstore/cosign/pull/2195)
* Bump github/codeql-action from 2.1.18 to 2.1.19 (https://github.com/sigstore/cosign/pull/2184)
* Bump github/codeql-action from 2.1.19 to 2.1.20 (https://github.com/sigstore/cosign/pull/2193)
* Bump google.golang.org/api from 0.92.0 to 0.93.0 (https://github.com/sigstore/cosign/pull/2183)
* Update Scorecard action to v2:alpha (https://github.com/sigstore/cosign/pull/2177)
* add stale workflow using the workflow template (https://github.com/sigstore/cosign/pull/2175)
* bump fulcio dep to 0.5.2 (https://github.com/sigstore/cosign/pull/2176)
* bump scaffold in tests to use release v0.4.5 (https://github.com/sigstore/cosign/pull/2180)

## Contributors

* Asra Ali (@asraa)
* Azeem Shaikh (@azeemshaikh38)
* Carlos Tadeu Panato Junior (@cpanato)
* Engin Diri (@dirien)
* Kenny Leung (@k4leung4)

# v1.11.0

## Enhancements

* use updated device flow logic with PKCE (https://github.com/sigstore/cosign/pull/2163)

## Bug Fixes

* fix panic when os.Stat returns an error besides ErrNotExists (https://github.com/sigstore/cosign/pull/2162)
* fix: add env cmd to root (https://github.com/sigstore/cosign/pull/2171)
* fix: rekor get tlog entry with uuid (https://github.com/sigstore/cosign/pull/2058)
* fix oidc post-merge job (https://github.com/sigstore/cosign/pull/2164)
* fix handling of verify-attestation types for URIs (https://github.com/sigstore/cosign/pull/2159)
* fix: adds envelope hash to in-toto entries in tlog entry creation (https://github.com/sigstore/cosign/pull/2118)
* fix: fix blob verification output (https://github.com/sigstore/cosign/pull/2157)
* Verify the certificate chain against the Fulcio root trust by default (https://github.com/sigstore/cosign/pull/2139)

## Documention

* docs: clarify wording in spec about usage of certificate chain (https://github.com/sigstore/cosign/pull/2152)
* Add notes to clarify registry use. (https://github.com/sigstore/cosign/pull/2145)

## Others

* Bump github.com/go-openapi/swag from 0.22.0 to 0.22.1 (https://github.com/sigstore/cosign/pull/2167)
* Bump sigstore/cosign-installer from 2.5.0 to 2.5.1 (https://github.com/sigstore/cosign/pull/2168)
* update e2e job to run only when push to main (https://github.com/sigstore/cosign/pull/2169)
* Remove third_party (https://github.com/sigstore/cosign/pull/2166)
* bump to scaffolding v0.4.4 (https://github.com/sigstore/cosign/pull/2165)
* Bump sigs.k8s.io/release-utils from 0.6.0 to 0.7.3 (https://github.com/sigstore/cosign/pull/2102)
* Run tests using Go 1.18 (https://github.com/sigstore/cosign/pull/2093)
* Bump actions/github-script from 6.1.0 to 6.1.1 (https://github.com/sigstore/cosign/pull/2156)
* Bump go.uber.org/atomic from 1.9.0 to 1.10.0 (https://github.com/sigstore/cosign/pull/2155)
* Bump github.com/xanzy/go-gitlab from 0.71.0 to 0.72.0 (https://github.com/sigstore/cosign/pull/2148)
* Bump tests to use scaffolding-0.4.3. (https://github.com/sigstore/cosign/pull/2153)
* Bump google.golang.org/api from 0.91.0 to 0.92.0 (https://github.com/sigstore/cosign/pull/2150)
* Bump actions/cache from 3.0.6 to 3.0.7 (https://github.com/sigstore/cosign/pull/2151)
* Use TUF from scaffolding for validating cosign. (https://github.com/sigstore/cosign/pull/2146)
* Bump github.com/hashicorp/go-secure-stdlib/parseutil from 0.1.6 to 0.1.7 (https://github.com/sigstore/cosign/pull/2141)
* Bump github.com/go-openapi/swag from 0.21.1 to 0.22.0 (https://github.com/sigstore/cosign/pull/2140)
* Bump github.com/xanzy/go-gitlab from 0.70.0 to 0.71.0 (https://github.com/sigstore/cosign/pull/2142)
* Bump actions/cache from 3.0.5 to 3.0.6 (https://github.com/sigstore/cosign/pull/2136)
* Bump github.com/go-piv/piv-go from 1.9.0 to 1.10.0 (https://github.com/sigstore/cosign/pull/2135)
* Bump github/codeql-action from 2.1.17 to 2.1.18 (https://github.com/sigstore/cosign/pull/2129)
* Update CHANGELOG for 1.10.1 release (https://github.com/sigstore/cosign/pull/2130)

## Contributors

* Asra Ali (@asraa)
* Batuhan Apaydın (@developer-guy)
* Bob Callaway (@bobcallaway)
* Carlos Tadeu Panato Junior (@cpanato)
* David Bendory (@bendory)
* Jason Hall (@imjasonh)
* Kazuma Watanabe (@wata727)
* Matt Moore (@mattmoor)
* Noah Kreiger (@nkreiger)
* Priya Wadhwa (@priyawadhwa)
* Samsondeen (@dsa0x)
* Ville Aikas (@vaikas)
* saso (@otms61)

# v1.10.1

**Note: This release comes with a fix for CVE-2022-35929 described in this [Github Security Advisory](https://github.com/sigstore/cosign/security/advisories/GHSA-vjxv-45g9-9296). Please upgrade to this release ASAP**

## Enhancements

* update cross-builder to go1.18.5 and cosign image to 1.10.0 (https://github.com/sigstore/cosign/pull/2119)
* feat: attach: attestation: allow passing multiple payloads (https://github.com/sigstore/cosign/pull/2085)
* Resolves #522 set Created date to time of execution (https://github.com/sigstore/cosign/pull/2108)
* Fix field names in the vulnerability attestation (https://github.com/sigstore/cosign/pull/2099)
* Change Result in Vulnerability Attestation to interface{} (https://github.com/sigstore/cosign/pull/2096)
* Improve error message when no sigs/atts are found for an image (https://github.com/sigstore/cosign/pull/2101)
* add flag to allow skipping upload to transparency log (https://github.com/sigstore/cosign/pull/2089)

## Documention

* chore: fix documentation and warning on using untrusted rekor key (https://github.com/sigstore/cosign/pull/2124)
* Enable Scorecard badge (https://github.com/sigstore/cosign/pull/2109)

## Bug Fixes

* Merge pull request from GHSA-vjxv-45g9-9296
* Correct the type used for attest (https://github.com/sigstore/cosign/pull/2128)

## Others

* Bump mikefarah/yq from 4.26.1 to 4.27.2 (https://github.com/sigstore/cosign/pull/2116)
* Bump github.com/open-policy-agent/opa from 0.42.2 to 0.43.0 (https://github.com/sigstore/cosign/pull/2115)
* Bump github.com/xanzy/go-gitlab from 0.69.0 to 0.70.0 (https://github.com/sigstore/cosign/pull/2120)
* Bump google.golang.org/api from 0.90.0 to 0.91.0 (https://github.com/sigstore/cosign/pull/2125)
* Bump google.golang.org/api from 0.89.0 to 0.90.0 (https://github.com/sigstore/cosign/pull/2111)
* Bump github/codeql-action from 2.1.16 to 2.1.17 (https://github.com/sigstore/cosign/pull/2112)
* Bump google.golang.org/protobuf from 1.28.0 to 1.28.1 (https://github.com/sigstore/cosign/pull/2110)
* Bump google.golang.org/api from 0.88.0 to 0.89.0 (https://github.com/sigstore/cosign/pull/2106)
* Bump imjasonh/setup-ko from 0.4 to 0.5 (https://github.com/sigstore/cosign/pull/2107)
* Introduce a custom error type to classify errors. (https://github.com/sigstore/cosign/pull/2114)
* Bump github.com/hashicorp/go-hclog from 1.2.1 to 1.2.2 (https://github.com/sigstore/cosign/pull/2103)
* remove style jobs and cleanup makefile gofmt and goimports are running already with golangci-lint (https://github.com/sigstore/cosign/pull/2105)
* Bump sigstore/cosign-installer from 2.4.1 to 2.5.0 (https://github.com/sigstore/cosign/pull/2100)
* Remove knative/pkg deps (https://github.com/sigstore/cosign/pull/2092)

## Contributors

* Asra Ali (@asraa)
* Azeem Shaikh (@azeemshaikh38)
* Carlos Tadeu Panato Junior (@cpanato)
* Furkan Türkal (@Dentrax)
* Jason Hall (@imjasonh)
* Kenny Leung (@k4leung4)
* Matt Moore (@mattmoor)
* Teppei Fukuda (@knqyf263)
* Tobias Trabelsi (@Lerentis)
* saso (@otms61)

# v1.10.0

## Enhancements

* Add env subcommand. (https://github.com/sigstore/cosign/pull/2051)
* feat: cert-extensions verify (https://github.com/sigstore/cosign/pull/1626)
* sign-blob: bundle should work independently (https://github.com/sigstore/cosign/pull/2016)
* Add --oidc-provider flag to specify which provider to use for ambient credentials (https://github.com/sigstore/cosign/pull/1998)
* Use pkg/fulcioroots and pkg/tuf from sigstore/sigstore (https://github.com/sigstore/cosign/pull/1866)
* Add --platform flag to cosign sbom download  (https://github.com/sigstore/cosign/pull/1975)
* Route deprectated  -version to subcommand (https://github.com/sigstore/cosign/pull/1854)
* Add cyclonedx predicate type for attestations (https://github.com/sigstore/cosign/pull/1977)
* Updated Azure kms commands. (https://github.com/sigstore/cosign/pull/1972)
* Add spdxjson predicate type for attestations (https://github.com/sigstore/cosign/pull/1974)
* Drop tuf client dependency on GCS client library (https://github.com/sigstore/cosign/pull/1967)
* feat(fulcioroots): singleton error pattern (https://github.com/sigstore/cosign/pull/1965)
* tuf: improve TUF client concurrency and caching (https://github.com/sigstore/cosign/pull/1953)
* Separate RegExp matching of issuer/subject from strict (https://github.com/sigstore/cosign/pull/1956)

## Documention

* update design doc link (https://github.com/sigstore/cosign/pull/2077)
* specs: fix list formatting on SIGNATURE_SPEC (https://github.com/sigstore/cosign/pull/2030)
* public-key: fix command description (https://github.com/sigstore/cosign/pull/2024)
* docs(readme): add installation steps for container image for cosign binary (https://github.com/sigstore/cosign/pull/1986)
* Add Cloudsmith Container Registry to tested registry list (https://github.com/sigstore/cosign/pull/1966)


## Bug Fixes

* Fix OIDC test  (https://github.com/sigstore/cosign/pull/2050)
* Use cosign.ConfirmPrompt more consistently (https://github.com/sigstore/cosign/pull/2039)
* chore: add note about SIGSTORE_REKOR_PUBLIC_KEY (https://github.com/sigstore/cosign/pull/2040)
* Fix #1378 create new attestation signature in replace mode if not existent (https://github.com/sigstore/cosign/pull/2014)
* encrypt values to create the github action secret  (https://github.com/sigstore/cosign/pull/1990)
* fix/update post build job (https://github.com/sigstore/cosign/pull/1983)
* fix typos (https://github.com/sigstore/cosign/pull/1982)

## Others

* Bump github.com/hashicorp/vault/sdk from 0.5.2 to 0.5.3 (https://github.com/sigstore/cosign/pull/2079)
* Bump github.com/go-openapi/strfmt from 0.21.2 to 0.21.3 (https://github.com/sigstore/cosign/pull/2078)
* Bump google.golang.org/api from 0.87.0 to 0.88.0 (https://github.com/sigstore/cosign/pull/2081)
* Remove hack/tools.go (https://github.com/sigstore/cosign/pull/2080)
* Remove replace directives in go.mod. (https://github.com/sigstore/cosign/pull/2070)
* Bump mikefarah/yq from 4.25.3 to 4.26.1 (https://github.com/sigstore/cosign/pull/2076)
* Bump github.com/xanzy/go-gitlab from 0.68.2 to 0.69.0 (https://github.com/sigstore/cosign/pull/2075)
* Bump actions/dependency-review-action from 2.0.2 to 2.0.4 (https://github.com/sigstore/cosign/pull/2073)
* Bump google.golang.org/api from 0.86.0 to 0.87.0 (https://github.com/sigstore/cosign/pull/2064)
* chore(deps): CycloneDX PredicateType changed to use in-toto-golang (https://github.com/sigstore/cosign/pull/2067)
* Bump github.com/open-policy-agent/opa from 0.42.0 to 0.42.2 (https://github.com/sigstore/cosign/pull/2063)
* Bump google.golang.org/grpc from 1.47.0 to 1.48.0 (https://github.com/sigstore/cosign/pull/2062)
* Bump actions/setup-go from 3.2.0 to 3.2.1 (https://github.com/sigstore/cosign/pull/2060)
* Bump github/codeql-action from 2.1.15 to 2.1.16 (https://github.com/sigstore/cosign/pull/2065)
* Bump actions/cache from 3.0.4 to 3.0.5 (https://github.com/sigstore/cosign/pull/2066)
* update to go 1.18 (https://github.com/sigstore/cosign/pull/2059)
* Bump github.com/open-policy-agent/opa from 0.35.0 to 0.42.0 (https://github.com/sigstore/cosign/pull/2046)
* update ct/otel and etcd (https://github.com/sigstore/cosign/pull/2054)
* remove tests with 1.21 k8s cluster because it is deprecated and add v1.23/24 (https://github.com/sigstore/cosign/pull/2055)
* Bump sigstore/cosign-installer from 2.4.0 to 2.4.1 (https://github.com/sigstore/cosign/pull/2042)
* Bump github.com/hashicorp/go-version from 1.5.0 to 1.6.0 (https://github.com/sigstore/cosign/pull/2032)
* Bump github.com/spiffe/go-spiffe/v2 from 2.1.0 to 2.1.1 (https://github.com/sigstore/cosign/pull/2037)
* Bump github/codeql-action from 2.1.14 to 2.1.15 (https://github.com/sigstore/cosign/pull/2038)
* Bump google.golang.org/api from 0.85.0 to 0.86.0 (https://github.com/sigstore/cosign/pull/2036)
* Bump github.com/stretchr/testify from 1.7.5 to 1.8.0 (https://github.com/sigstore/cosign/pull/2035)
* Bump ossf/scorecard-action from 1.1.1 to 1.1.2 (https://github.com/sigstore/cosign/pull/2033)
* Bump github.com/xanzy/go-gitlab from 0.68.0 to 0.68.2 (https://github.com/sigstore/cosign/pull/2029)
* Bump github.com/stretchr/testify from 1.7.4 to 1.7.5 (https://github.com/sigstore/cosign/pull/2026)
* Attempt to clean up pkg/cosign (https://github.com/sigstore/cosign/pull/2018)
* Bump github/codeql-action from 2.1.13 to 2.1.14 (https://github.com/sigstore/cosign/pull/2023)
* Bump github.com/google/go-containerregistry from 0.9.0 to 0.10.0 (https://github.com/sigstore/cosign/pull/2021)
* Bump mikefarah/yq from 4.25.2 to 4.25.3 (https://github.com/sigstore/cosign/pull/2022)
* Bump google.golang.org/api from 0.84.0 to 0.85.0 (https://github.com/sigstore/cosign/pull/2015)
* Bump github.com/stretchr/testify from 1.7.3 to 1.7.4 (https://github.com/sigstore/cosign/pull/2010)
* Bump github.com/google/go-github/v45 from 45.1.0 to 45.2.0 (https://github.com/sigstore/cosign/pull/2011)
* Bump github.com/spf13/cobra from 1.4.0 to 1.5.0 (https://github.com/sigstore/cosign/pull/2012)
* Bump github/codeql-action from 2.1.12 to 2.1.13 (https://github.com/sigstore/cosign/pull/2013)
* Bump github.com/stretchr/testify from 1.7.2 to 1.7.3 (https://github.com/sigstore/cosign/pull/2009)
* Bump actions/dependency-review-action from 2.0.1 to 2.0.2 (https://github.com/sigstore/cosign/pull/2001)
* Bump github.com/hashicorp/vault/sdk from 0.5.1 to 0.5.2 (https://github.com/sigstore/cosign/pull/1996)
* Bump actions/dependency-review-action from 1.0.2 to 2.0.1 (https://github.com/sigstore/cosign/pull/2000)
* Bump google.golang.org/api from 0.83.0 to 0.84.0 (https://github.com/sigstore/cosign/pull/1999)
* Bump sigstore/sigstore to HEAD (https://github.com/sigstore/cosign/pull/1995)
* Bump github.com/hashicorp/vault/sdk from 0.5.0 to 0.5.1 (https://github.com/sigstore/cosign/pull/1988)
* cleanup ci job and remove policy-controller references (https://github.com/sigstore/cosign/pull/1981)
* Bump google.golang.org/api from 0.82.0 to 0.83.0 (https://github.com/sigstore/cosign/pull/1979)
* cleanup: unexport kubernetes.Client method (https://github.com/sigstore/cosign/pull/1973)
* Remove policy-controller now that it lives in sigstore/policy-controller (https://github.com/sigstore/cosign/pull/1976)
* Bump sigstore/cosign-installer from 2.3.0 to 2.4.0 (https://github.com/sigstore/cosign/pull/1980)
* Bump actions/cache from 3.0.3 to 3.0.4 (https://github.com/sigstore/cosign/pull/1970)
* Bump github.com/hashicorp/go-hclog from 1.2.0 to 1.2.1 (https://github.com/sigstore/cosign/pull/1968)
* Bump github.com/stretchr/testify from 1.7.1 to 1.7.2 (https://github.com/sigstore/cosign/pull/1963)
* Bump google.golang.org/grpc from 1.46.2 to 1.47.0 (https://github.com/sigstore/cosign/pull/1943)
* Bump github.com/hashicorp/go-secure-stdlib/parseutil from 0.1.5 to 0.1.6 (https://github.com/sigstore/cosign/pull/1958)
* replace gcr.io/distroless/ to use ghcr.io/distroless/ (https://github.com/sigstore/cosign/pull/1961)
* Bump github/codeql-action from 2.1.11 to 2.1.12 (https://github.com/sigstore/cosign/pull/1951)
* Bump google.golang.org/api from 0.81.0 to 0.82.0 (https://github.com/sigstore/cosign/pull/1948)

## Contributors

* Adolfo García Veytia (@puerco)
* Asra Ali (@asraa)
* Batuhan Apaydın (@developer-guy)
* Billy Lynch (@wlynch)
* Bob Callaway (@bobcallaway)
* Carlos Tadeu Panato Junior (@cpanato)
* Ciara Carey (@ciaracarey)
* Frederik Boster (@Syquel)
* Furkan Türkal (@Dentrax)
* Hector Fernandez (@hectorj2f)
* Jason Hall (@imjasonh)
* Jinhong Brejnholt (@JBrejnholt)
* Josh Dolitsky (@jdolitsky)
* Masahiro331 (@masahiro331)
* Priya Wadhwa (@priyawadhwa)
* Ville Aikas (@vaikas)
* William Woodruff (@woodruffw)

# v1.9.0

## Enhancements

* Do not push to public rekor. (https://github.com/sigstore/cosign/pull/1931)
* Add privacy statement for PII storage (https://github.com/sigstore/cosign/pull/1909)
* Add support for "**" in image glob matching (https://github.com/sigstore/cosign/pull/1914)
* [cosigned] Rename cosigned references to policy-controller (https://github.com/sigstore/cosign/pull/1893)
* [cosigned] Remove undefined apiGroups from policy clusterrole (https://github.com/sigstore/cosign/pull/1896)
* tree: support --attachment-tag-prefix (https://github.com/sigstore/cosign/pull/1900)
* v1beta1 API for cosigned (https://github.com/sigstore/cosign/pull/1890)
* tree: only report artifacts that are present (https://github.com/sigstore/cosign/pull/1872)
* Check certificate policy flags with only a certificate (https://github.com/sigstore/cosign/pull/1869)
* Normalize certificate flag names (https://github.com/sigstore/cosign/pull/1868)
* Add rekor.0.pub TUF target to unit tests (https://github.com/sigstore/cosign/pull/1860)
* If SBOM ref has .json suffix, assume JSON mediatype (https://github.com/sigstore/cosign/pull/1859)
* sget: Enable KMS providers for sget (https://github.com/sigstore/cosign/pull/1852)
* Use filepath match instead of glob (https://github.com/sigstore/cosign/pull/1842)
* cosigned: Fix podAntiAffinity labels (https://github.com/sigstore/cosign/pull/1841)
* Add function to explictly request a certain provider (https://github.com/sigstore/cosign/pull/1837)
* Validate tlog entry when verifying signature via public key. (https://github.com/sigstore/cosign/pull/1833)
* New flag --oidc-providers-disable to disable OIDC providers (https://github.com/sigstore/cosign/pull/1832)
* Add auth flow option to KeyOpts. (https://github.com/sigstore/cosign/pull/1827)
* cosigned: Test unsupported KMS providers (https://github.com/sigstore/cosign/pull/1820)
* Refactor fulcio signer to take in KeyOpts (take 2) (https://github.com/sigstore/cosign/pull/1818)
* feat: add rego policy support (https://github.com/sigstore/cosign/pull/1817)
* [Cosigned] Add signature pull secrets (https://github.com/sigstore/cosign/pull/1805)
* Check failure message of policy that fails with issuer mismatch (https://github.com/sigstore/cosign/pull/1815)
* Support PKCS1 encoded and non-ECDSA CT log public keys (https://github.com/sigstore/cosign/pull/1806)

## Documention

* update README with ebpf modules (https://github.com/sigstore/cosign/pull/1888)
* Point git commmit FUN.md to gitsign! (https://github.com/sigstore/cosign/pull/1874)
* Add IBM Cloud Container Registry to tested registry list (https://github.com/sigstore/cosign/pull/1856)
* Document Staging instance usage with Keyless (https://github.com/sigstore/cosign/pull/1824)

## Bug Fixes

* fix: fix #1930 for AWS KMS formats (https://github.com/sigstore/cosign/pull/1946)
* fix: fix fetching updated targets from TUF root (https://github.com/sigstore/cosign/pull/1921)
* Fix piv-tool generate-key command in TOKENS doc (https://github.com/sigstore/cosign/pull/1850)

## Others

* remove deprecation (https://github.com/sigstore/cosign/pull/1952)
* Bump github.com/aws/aws-sdk-go-v2 from 1.14.0 to 1.16.4 (https://github.com/sigstore/cosign/pull/1949)
* update cross-builder image to use go1.17.11 (https://github.com/sigstore/cosign/pull/1950)
* Bump ossf/scorecard-action from 1.1.0 to 1.1.1 (https://github.com/sigstore/cosign/pull/1945)
* Bump github.com/secure-systems-lab/go-securesystemslib (https://github.com/sigstore/cosign/pull/1944)
* Bump actions/cache from 3.0.2 to 3.0.3 (https://github.com/sigstore/cosign/pull/1937)
* Bump mikefarah/yq from 4.25.1 to 4.25.2 (https://github.com/sigstore/cosign/pull/1933)
* Bump github.com/spf13/viper from 1.11.0 to 1.12.0 (https://github.com/sigstore/cosign/pull/1924)
* Bump github.com/hashicorp/vault/sdk from 0.4.1 to 0.5.0 (https://github.com/sigstore/cosign/pull/1926)
* Bump actions/setup-go from 3.1.0 to 3.2.0 (https://github.com/sigstore/cosign/pull/1927)
* Bump actions/dependency-review-action from 1.0.1 to 1.0.2 (https://github.com/sigstore/cosign/pull/1915)
* Bump google-github-actions/auth from 0.7.3 to 0.8.0 (https://github.com/sigstore/cosign/pull/1916)
* Bump ossf/scorecard-action from 1.0.4 to 1.1.0 (https://github.com/sigstore/cosign/pull/1922)
* Bump google.golang.org/api from 0.80.0 to 0.81.0 (https://github.com/sigstore/cosign/pull/1918)
* Bump github.com/armon/go-metrics from 0.3.11 to 0.4.0 (https://github.com/sigstore/cosign/pull/1919)
* Bump github.com/xanzy/go-gitlab from 0.66.0 to 0.68.0 (https://github.com/sigstore/cosign/pull/1920)
* Bump github.com/xanzy/go-gitlab from 0.65.0 to 0.66.0 (https://github.com/sigstore/cosign/pull/1913)
* Move deprecated dependency: google/trillian/merkle to transparency-dev (https://github.com/sigstore/cosign/pull/1910)
* Bump github.com/hashicorp/go-version from 1.4.0 to 1.5.0 (https://github.com/sigstore/cosign/pull/1902)
* Bump github.com/hashicorp/go-secure-stdlib/parseutil from 0.1.4 to 0.1.5 (https://github.com/sigstore/cosign/pull/1883)
* Bump cloud.google.com/go/storage from 1.22.0 to 1.22.1 (https://github.com/sigstore/cosign/pull/1906)
* Bump actions/upload-artifact from 3.0.0 to 3.1.0 (https://github.com/sigstore/cosign/pull/1907)
* The timeout arg in golangci-lint has been moved to the generic args param. (https://github.com/sigstore/cosign/pull/1901)
* Update go-tuf (https://github.com/sigstore/cosign/pull/1894)
* Bump google.golang.org/api from 0.79.0 to 0.80.0 (https://github.com/sigstore/cosign/pull/1897)
* Bump google-github-actions/auth from 0.7.2 to 0.7.3 (https://github.com/sigstore/cosign/pull/1898)
* Bump github/codeql-action from 2.1.10 to 2.1.11 (https://github.com/sigstore/cosign/pull/1891)
* Update github.com/google/go-containerregistry/pkg/authn/k8schain module to f1b065c6cb3d (https://github.com/sigstore/cosign/pull/1889)
* Remove dependency on deprecated github.com/pkg/errors (https://github.com/sigstore/cosign/pull/1887)
* Bump google.golang.org/grpc from 1.46.0 to 1.46.2 (https://github.com/sigstore/cosign/pull/1884)
* Bump google-github-actions/auth from 0.7.1 to 0.7.2 (https://github.com/sigstore/cosign/pull/1886)
* go.mod: format go.mod (https://github.com/sigstore/cosign/pull/1879)
* chore: remove regex from image pattern (https://github.com/sigstore/cosign/pull/1873)
* Bump actions/dependency-review-action (https://github.com/sigstore/cosign/pull/1875)
* Bump actions/github-script from 6.0.0 to 6.1.0 (https://github.com/sigstore/cosign/pull/1876)
* Bump actions/setup-go from 3.0.0 to 3.1.0 (https://github.com/sigstore/cosign/pull/1870)
* Update go to 1.17.10 / cosign image to 1.18.0 and actions setup go (https://github.com/sigstore/cosign/pull/1861)
* Bump github/codeql-action from 2.1.9 to 2.1.10 (https://github.com/sigstore/cosign/pull/1863)
* Bump golangci/golangci-lint-action from 3.1.0 to 3.2.0 (https://github.com/sigstore/cosign/pull/1864)
* Bump google.golang.org/api from 0.78.0 to 0.79.0 (https://github.com/sigstore/cosign/pull/1858)
* Bump github.com/xanzy/go-gitlab from 0.64.0 to 0.65.0 (https://github.com/sigstore/cosign/pull/1857)
* Bump github.com/go-openapi/runtime from 0.24.0 to 0.24.1 (https://github.com/sigstore/cosign/pull/1851)
* remove exclude from go.mod (https://github.com/sigstore/cosign/pull/1846)
* Bump github.com/hashicorp/go-plugin from 1.4.3 to 1.4.4 (https://github.com/sigstore/cosign/pull/1843)
* Bump google.golang.org/api from 0.77.0 to 0.78.0 (https://github.com/sigstore/cosign/pull/1838)
* Bump mikefarah/yq from 4.24.5 to 4.25.1 (https://github.com/sigstore/cosign/pull/1831)
* Bump google.golang.org/api from 0.76.0 to 0.77.0 (https://github.com/sigstore/cosign/pull/1829)
* Bump github.com/go-openapi/runtime from 0.23.3 to 0.24.0 (https://github.com/sigstore/cosign/pull/1830)
* Bump github.com/spiffe/go-spiffe/v2 from 2.0.0 to 2.1.0 (https://github.com/sigstore/cosign/pull/1828)
* chore(deps): Included dependency review (https://github.com/sigstore/cosign/pull/1792)
* Bump sigstore/cosign-installer from 2.2.1 to 2.3.0 (https://github.com/sigstore/cosign/pull/1813)
* Bump github/codeql-action from 2.1.8 to 2.1.9 (https://github.com/sigstore/cosign/pull/1814)
* Bump google.golang.org/api from 0.75.0 to 0.76.0 (https://github.com/sigstore/cosign/pull/1810)
* Bump github.com/google/go-cmp from 0.5.7 to 0.5.8 (https://github.com/sigstore/cosign/pull/1809)
* Bump github.com/armon/go-metrics from 0.3.10 to 0.3.11 (https://github.com/sigstore/cosign/pull/1808)

## Contributors

* Asra Ali (@asraa)
* Adolfo García Veytia (@puerco)
* Andrés Torres (@elfotografo007)
* Billy Lynch (@wlynch)
* Carlos Tadeu Panato Junior (@cpanato)
* Dan Lorenc (@dlorenc)
* Denny (@DennyHoang)
* Eitan Yarmush (@EItanya)
* Hayden Blauzvern (@haydentherapper)
* Hector Fernandez (@hectorj2f)
* Jack Baines (@bainsy88)
* Jason Hall (@imjasonh)
* Josh Dolitsky (@jdolitsky)
* Kenny Leung (@k4leung4)
* Koichi Shiraishi (@zchee)
* Naveen Srinivasan (@naveensrinivasan)
* Neal McBurnett (@nealmcb)
* Priya Wadhwa (@priyawadhwa)
* Rob Best (@ribbybibby)
* Tomasz Janiszewski (@janisz)
* Ville Aikas (@vaikas)
* Vladimir Nachev (@vpnachev)


# v1.8.0

_NOTE_: If you use Fulcio to issue certificates you will need to use this release.

## Enhancements

* Support PKCS1 encoded and non-ECDSA CT log public keys (https://github.com/sigstore/cosign/pull/1806)
* Load in intermediate cert pool from TUF (https://github.com/sigstore/cosign/pull/1804)
* Don't fail open in VerifyBundle (https://github.com/sigstore/cosign/pull/1648)
* Handle context cancelled properly + tests. (https://github.com/sigstore/cosign/pull/1796)
* Allow passing keys via environment variables (`env://` refs) (https://github.com/sigstore/cosign/pull/1794)
* Add parallelization for processing policies / authorities. (https://github.com/sigstore/cosign/pull/1795)
* Attestations + policy in cip. (https://github.com/sigstore/cosign/pull/1772)
* Refactor fulcio signer to take in KeyOpts. (https://github.com/sigstore/cosign/pull/1788)
* Remove the dependency on v1alpha1.Identity which brings in (https://github.com/sigstore/cosign/pull/1790)
* Add Fulcio intermediate CA certificate to intermediate pool (https://github.com/sigstore/cosign/pull/1774)
* Cosigned validate against remote sig src (https://github.com/sigstore/cosign/pull/1754)
* tuf: add debug info if tuf update fails (https://github.com/sigstore/cosign/pull/1766)
* Break the CIP action tests into a sh script. (https://github.com/sigstore/cosign/pull/1767)
* [policy-webhook] The webhooks name is now configurable via --(validating|mutating)-webhook-name flags (https://github.com/sigstore/cosign/pull/1757)
* Verify embedded SCTs (https://github.com/sigstore/cosign/pull/1731)
* Validate issuer/subject regexp in validate webhook. (https://github.com/sigstore/cosign/pull/1761)
* Add intermediate CA certificate pool for Fulcio (https://github.com/sigstore/cosign/pull/1749)
* [cosigned] The webhook name is now configurable via --webhook-name flag (https://github.com/sigstore/cosign/pull/1726)
* Use bundle log ID to find verification key (https://github.com/sigstore/cosign/pull/1748)
* Refactor policy related code, add support for vuln verify (https://github.com/sigstore/cosign/pull/1747)
* Create convert functions for internal CIP (https://github.com/sigstore/cosign/pull/1736)
* Move the KMS integration imports into the binary entrypoints (https://github.com/sigstore/cosign/pull/1744)

## Bug Fixes

* Fix a bug where an error would send duplicate results. (https://github.com/sigstore/cosign/pull/1797)
* fix: more informative error (https://github.com/sigstore/cosign/pull/1778)
* fix: add support for rsa keys (https://github.com/sigstore/cosign/pull/1768)
* Implement identities, fix bug in webhook validation. (https://github.com/sigstore/cosign/pull/1759)

## Others

* update changelog for 1.8.0 (https://github.com/sigstore/cosign/pull/1807)
* add changelog for release v1.8.0 (https://github.com/sigstore/cosign/pull/1803)
* Bump github.com/hashicorp/go-retryablehttp from 0.7.0 to 0.7.1 (https://github.com/sigstore/cosign/pull/1758)
* Bump google-github-actions/auth from 0.7.0 to 0.7.1 (https://github.com/sigstore/cosign/pull/1801)
* Bump google.golang.org/grpc from 1.45.0 to 1.46.0 (https://github.com/sigstore/cosign/pull/1800)
* Bump github.com/xanzy/go-gitlab from 0.63.0 to 0.64.0 (https://github.com/sigstore/cosign/pull/1799)
* Revert "Refactor fulcio signer to take in KeyOpts. (https://github.com/sigstore/cosign/pull/1788)" (https://github.com/sigstore/cosign/pull/1798)
* chore: add rego function to consume modules (https://github.com/sigstore/cosign/pull/1787)
* test: add cue unit tests (https://github.com/sigstore/cosign/pull/1791)
* Run update-codegen. (https://github.com/sigstore/cosign/pull/1789)
* Bump actions/checkout from 3.0.1 to 3.0.2 (https://github.com/sigstore/cosign/pull/1783)
* Bump github.com/mitchellh/mapstructure from 1.4.3 to 1.5.0 (https://github.com/sigstore/cosign/pull/1782)
* Bump k8s.io/code-generator from 0.23.5 to 0.23.6 (https://github.com/sigstore/cosign/pull/1781)
* Bump google.golang.org/api from 0.74.0 to 0.75.0 (https://github.com/sigstore/cosign/pull/1780)
* Bump cuelang.org/go from 0.4.2 to 0.4.3 (https://github.com/sigstore/cosign/pull/1779)
* Bump codecov/codecov-action from 3.0.0 to 3.1.0 (https://github.com/sigstore/cosign/pull/1784)
* Bump actions/checkout from 3.0.0 to 3.0.1 (https://github.com/sigstore/cosign/pull/1764)
* Bump mikefarah/yq from 4.24.4 to 4.24.5 (https://github.com/sigstore/cosign/pull/1765)
* chore: add warning when downloading a sBOM (https://github.com/sigstore/cosign/pull/1763)
* chore: add warn when attaching sBOM (https://github.com/sigstore/cosign/pull/1756)
* Bump sigstore/cosign-installer from 2.2.0 to 2.2.1 (https://github.com/sigstore/cosign/pull/1752)
* update go builder and cosign images (https://github.com/sigstore/cosign/pull/1755)
* test: create fake TUF test root and create test SETs for verification (https://github.com/sigstore/cosign/pull/1750)
* Bump github.com/spf13/viper from 1.10.1 to 1.11.0 (https://github.com/sigstore/cosign/pull/1751)
* Bump mikefarah/yq from 4.24.2 to 4.24.4 (https://github.com/sigstore/cosign/pull/1746)
* Bump github.com/xanzy/go-gitlab from 0.62.0 to 0.63.0 (https://github.com/sigstore/cosign/pull/1745)

## Contributors

* Asra Ali (@asraa)
* Billy Lynch (@wlynch)
* Carlos Tadeu Panato Junior (@cpanato)
* Denny (@DennyHoang)
* Hayden Blauzvern (@haydentherapper)
* Hector Fernandez (@hectorj2f)
* Matt Moore (@mattmoor)
* Ville Aikas (@vaikas)
* Vladimir Nachev (@vpnachev)
* Youssef Bel Mekki (@ybelMekk)
* Zack Newman (@znewman01)

# v1.7.2

## Bug Fixes

* Make public all types required to use ValidatePolicy (https://github.com/sigstore/cosign/pull/1727)
* fix: add permissions to patch events (https://github.com/sigstore/cosign/pull/1722)
* Fix publicKey unmarshal (https://github.com/sigstore/cosign/pull/1719)
* Update release job (https://github.com/sigstore/cosign/pull/1720)
* Makefile: fix directory not found error (https://github.com/sigstore/cosign/pull/1718)

## Others

* Remove newline from download sbom output (https://github.com/sigstore/cosign/pull/1732)
* Bump github.com/hashicorp/go-uuid from 1.0.2 to 1.0.3 (https://github.com/sigstore/cosign/pull/1724)
* Add unit tests for IntotoAttestation verifier. (https://github.com/sigstore/cosign/pull/1728)
* Bump github/codeql-action from 2.1.7 to 2.1.8 (https://github.com/sigstore/cosign/pull/1725)
* Bump cloud.google.com/go/storage from 1.21.0 to 1.22.0 (https://github.com/sigstore/cosign/pull/1721)
* Bump sigstore/cosign-installer from 2.1.0 to 2.2.0 (https://github.com/sigstore/cosign/pull/1723)
* Bump github.com/xanzy/go-gitlab from 0.61.0 to 0.62.0 (https://github.com/sigstore/cosign/pull/1711)
* Bump google-github-actions/auth from 0.6.0 to 0.7.0 (https://github.com/sigstore/cosign/pull/1712)
* Bump github/codeql-action from 2.1.6 to 2.1.7 (https://github.com/sigstore/cosign/pull/1713)
* Bump codecov/codecov-action from 2.1.0 to 3 (https://github.com/sigstore/cosign/pull/1714)

## Contributors

* Carlos Tadeu Panato Junior (@cpanato)
* Denny (@DennyHoang)
* Hector Fernandez (@hectorj2f)
* Josh Dolitsky (@jdolitsky)
* Rob Best (@ribbybibby)
* Ville Aikas (@vaikas)

# v1.7.1

## Bug Fixes

* commenting out the copy from gcr to ghcr due issues on github side (https://github.com/sigstore/cosign/pull/1715)

# v1.7.0

## Enhancements

* sign: set the oidc redirect uri (https://github.com/sigstore/cosign/pull/1675)
* Use ValidatePubKey from sigstore/sigstore (https://github.com/sigstore/cosign/pull/1676)
* Remove the hardcoded sigstore audience (https://github.com/sigstore/cosign/pull/1698)
* verify: remove extra calls to rekor for verify and verify-blob (https://github.com/sigstore/cosign/pull/1694)
* add leaf hash verification (https://github.com/sigstore/cosign/pull/1688)
* cosign clean: Don't log failure if the registry responds with 404 (https://github.com/sigstore/cosign/pull/1687)
* Update error message for verify/verify attestation (https://github.com/sigstore/cosign/pull/1686)
* change file_name_template to PackageName (https://github.com/sigstore/cosign/pull/1683)
* Make `cosign copy` copy metadata attached to child images. (https://github.com/sigstore/cosign/pull/1682)
* Add support for cert and cert chain flags with PKCS11 tokens (https://github.com/sigstore/cosign/pull/1671)
* Find all valid entries in verify-blob (https://github.com/sigstore/cosign/pull/1673)
* Refactor based on discussions in #1650 (https://github.com/sigstore/cosign/pull/1674)
* feat: add ability to override registry keychain (https://github.com/sigstore/cosign/pull/1666)
* Add specific suffixes mediaTypes to sboms (https://github.com/sigstore/cosign/pull/1663)
* Add certificate chain flag for signing (https://github.com/sigstore/cosign/pull/1656)
* First batch of followups to #1650 (https://github.com/sigstore/cosign/pull/1664)
* Add support for certificate chain to verify certificate (https://github.com/sigstore/cosign/pull/1659)
* Use syscall.Stdin for input handle. Fixes #1153 (https://github.com/sigstore/cosign/pull/1657)
* Shorten example OAuth URL (https://github.com/sigstore/cosign/pull/1661)
* Prompt user before running `cosign clean` (https://github.com/sigstore/cosign/pull/1649)
* Add support for intermediate certificates when verifiying (https://github.com/sigstore/cosign/pull/1631)
* feat: tree command utility (https://github.com/sigstore/cosign/pull/1603)
* Validate authority keys (https://github.com/sigstore/cosign/pull/1623)
* improve cosigned validation error messages (https://github.com/sigstore/cosign/pull/1618)
* Init entity from ociremote when signing a digest ref (https://github.com/sigstore/cosign/pull/1616)
* Add two env variables. One for using Rekor public key from OOB and (https://github.com/sigstore/cosign/pull/1610)
* Ensure entry is removed from CM on secret error. (https://github.com/sigstore/cosign/pull/1605)
* Validate a public key in a secret is valid. (https://github.com/sigstore/cosign/pull/1602)
* Add public key validation (https://github.com/sigstore/cosign/pull/1598)
* Add ability to inline secrets from SecretRef to configmap. (https://github.com/sigstore/cosign/pull/1595)
* 1417 policy validations (https://github.com/sigstore/cosign/pull/1548)
* Support deletion of ClusterImagePolicy (https://github.com/sigstore/cosign/pull/1580)
* Start of the necessary pieces to get #1418 and #1419 implemented (https://github.com/sigstore/cosign/pull/1562)

## Bug Fixes

* Fix handling of policy in verify-attestation (https://github.com/sigstore/cosign/pull/1672)
* Fix relative paths in Gitub OIDC blob test (https://github.com/sigstore/cosign/pull/1677)
* fix build date format for version command (https://github.com/sigstore/cosign/pull/1644)
* Fix 1608, 1613 (https://github.com/sigstore/cosign/pull/1617)
* Fix copy/paste mistake in repo name. (https://github.com/sigstore/cosign/pull/1600)
* Fix #1592 move authorities as siblings of images. (https://github.com/sigstore/cosign/pull/1593)
* Fix piping 'cosign verify' using fulcio/rekor (https://github.com/sigstore/cosign/pull/1590)
* Fix #1583 #1582. Disallow regex now until implemented. (https://github.com/sigstore/cosign/pull/1584)
* Don't lowercase input image refs, just fail (https://github.com/sigstore/cosign/pull/1586)

## Documention

* Document Elastic container registry support (https://github.com/sigstore/cosign/pull/1641)
* FUN.md broke when RecordObj changed to HashedRecordObj (https://github.com/sigstore/cosign/pull/1633)
* Add example using AWS Key Management Service (KMS) (https://github.com/sigstore/cosign/pull/1564)


## Others

* Use the github actions from sigstore/scaffolding. (https://github.com/sigstore/cosign/pull/1699)
* Bump google.golang.org/api from 0.73.0 to 0.74.0 (https://github.com/sigstore/cosign/pull/1695)
* Bump github/codeql-action from 1.1.5 to 2.1.6 (https://github.com/sigstore/cosign/pull/1690)
* Bump actions/cache from 3.0.0 to 3.0.1 (https://github.com/sigstore/cosign/pull/1689)
* Add e2e test for attest / verify-attestation (https://github.com/sigstore/cosign/pull/1685)
* Use cosign @ HEAD for Github OIDC sign blob test (https://github.com/sigstore/cosign/pull/1678)
* Bump mikefarah/yq from 4.23.1 to 4.24.2 (https://github.com/sigstore/cosign/pull/1670)
* remove replace directive (https://github.com/sigstore/cosign/pull/1669)
* update font when output the cosign version (https://github.com/sigstore/cosign/pull/1668)
* Use ClusterImagePolicy with Keyless + e2e tests for CIP with kind (https://github.com/sigstore/cosign/pull/1650)
* Bump google.golang.org/protobuf from 1.27.1 to 1.28.0 (https://github.com/sigstore/cosign/pull/1646)
* Bump mikefarah/yq from 4.22.1 to 4.23.1 (https://github.com/sigstore/cosign/pull/1639)
* Bump actions/cache from 2.1.7 to 3 (https://github.com/sigstore/cosign/pull/1640)
* Bump github.com/go-openapi/runtime from 0.23.2 to 0.23.3 (https://github.com/sigstore/cosign/pull/1638)
* Add extra label and change the latest tag to unstable for non tagged releases (https://github.com/sigstore/cosign/pull/1637)
* push latest tag when building a release (https://github.com/sigstore/cosign/pull/1636)
* update crane to v0.8.0 release (https://github.com/sigstore/cosign/pull/1635)
* Bump github.com/xanzy/go-gitlab from 0.59.0 to 0.60.0 (https://github.com/sigstore/cosign/pull/1634)
* Included OpenSSF Best Practices Badge (https://github.com/sigstore/cosign/pull/1628)
* Use latest knative/pkg's configmap informer (https://github.com/sigstore/cosign/pull/1615)
* Bump github.com/stretchr/testify from 1.7.0 to 1.7.1 (https://github.com/sigstore/cosign/pull/1621)
* Bump google.golang.org/api from 0.72.0 to 0.73.0 (https://github.com/sigstore/cosign/pull/1619)
* Bump github/codeql-action from 1.1.4 to 1.1.5 (https://github.com/sigstore/cosign/pull/1622)
* Bump ecr-login to pick up WithLogger rename (https://github.com/sigstore/cosign/pull/1624)
* Bump to knative pkg 1.3 (https://github.com/sigstore/cosign/pull/1614)
* Bump google.golang.org/api from 0.71.0 to 0.72.0 (https://github.com/sigstore/cosign/pull/1612)
* Use reusuable release workflow in sigstore/sigstore (https://github.com/sigstore/cosign/pull/1599)
* Bump github.com/spiffe/go-spiffe/v2 from 2.0.0-beta.12 to 2.0.0 (https://github.com/sigstore/cosign/pull/1597)
* Bump mikefarah/yq from 4.21.1 to 4.22.1 (https://github.com/sigstore/cosign/pull/1589)
* Bump google.golang.org/grpc from 1.44.0 to 1.45.0 (https://github.com/sigstore/cosign/pull/1587)
* Bump github.com/spf13/cobra from 1.3.0 to 1.4.0 (https://github.com/sigstore/cosign/pull/1588)
* Bump github.com/xanzy/go-gitlab from 0.58.0 to 0.59.0 (https://github.com/sigstore/cosign/pull/1579)
* Bump google-github-actions/setup-gcloud from 0.5.1 to 0.6.0 (https://github.com/sigstore/cosign/pull/1578)
* Bump github.com/hashicorp/go-hclog from 1.1.0 to 1.2.0 (https://github.com/sigstore/cosign/pull/1576)
* Bump google.golang.org/api from 0.70.0 to 0.71.0 (https://github.com/sigstore/cosign/pull/1577)
* Bump github/codeql-action from 1.1.3 to 1.1.4 (https://github.com/sigstore/cosign/pull/1565)
* add definition for artifact hub to verify the ownership (https://github.com/sigstore/cosign/pull/1563)
* Bump sigstore/cosign-installer from 2.0.1 to 2.1.0 (https://github.com/sigstore/cosign/pull/1561)
* Bump github.com/go-openapi/runtime from 0.23.1 to 0.23.2 (https://github.com/sigstore/cosign/pull/1559)
* Bump github.com/xanzy/go-gitlab from 0.57.0 to 0.58.0 (https://github.com/sigstore/cosign/pull/1560)
* Update hashicorp/parseutil to v0.1.3. (https://github.com/sigstore/cosign/pull/1557)
* Mirror signed release images from GCR to GHCR as part of release with Cloud Build. (https://github.com/sigstore/cosign/pull/1547)
* Bump github.com/xanzy/go-gitlab from 0.56.0 to 0.57.0 (https://github.com/sigstore/cosign/pull/1552)
* Bump actions/upload-artifact from 2.3.1 to 3 (https://github.com/sigstore/cosign/pull/1553)
* pkcs11: fix build instructions (https://github.com/sigstore/cosign/pull/1550)
* Update images for release job (https://github.com/sigstore/cosign/pull/1551)

## Contributors

* Adam A.G. Shamblin (@coyote240)
* Adolfo García Veytia (@puerco)
* Asra Ali (@asraa)
* Batuhan Apaydın (@developer-guy)
* Carlos Tadeu Panato Junior (@cpanato)
* Dan Lorenc (@dlorenc)
* Davi Garcia (@davivcgarcia)
* Hayden Blauzvern (@haydentherapper)
* Hector Fernandez (@hectorj2f)
* James Strong (@strongjz)
* Jason Hall (@imjasonh)
* Kavitha (@kkavitha)
* Kenny Leung (@k4leung4)
* Luiz Carvalho (@lcarva)
* Marco Franssen (@marcofranssen)
* Mark Percival (@mdp)
* Matt Moore (@mattmoor)
* Maxime Gréau (@mgreau)
* Mitch Thomas (@MitchellJThomas)
* Naveen Srinivasan (@naveensrinivasan)
* Nghia Tran (@tcnghia)
* Priya Wadhwa (@priyawadhwa)
* Radoslav Gerganov (@rgerganov)
* Thomas Strömberg (@tstromberg)
* Ville Aikas (@vaikas)
* noamichael (@noamichael)

# v1.6.0

## Security Fixes

* CVE-2022-23649 - Make sure signature in Rekor bundle matches signature being verified

## Enhancements

* Change Fulcio URL default to be fulcio.sigstore.dev (https://github.com/sigstore/cosign/pull/1529)
* Add CertExtensions func to extract all extensions (https://github.com/sigstore/cosign/pull/1515)
* Add a dummy.go file to allow vendoring config (https://github.com/sigstore/cosign/pull/1520)
* Add skeleton reconciler for cosigned API CRD. (https://github.com/sigstore/cosign/pull/1513)
* use v6 api calls (https://github.com/sigstore/cosign/pull/1511)
* This sets up the scaffolding for the `cosigned` CRD types. (https://github.com/sigstore/cosign/pull/1504)
* add correct layer media type to attach attestation (https://github.com/sigstore/cosign/pull/1503)
* Pick up some of the shared workflows (https://github.com/sigstore/cosign/pull/1490)
* feat: support other types in copy cmd (https://github.com/sigstore/cosign/pull/1493)
* Pick up a change to quiet ECR-login logging. (https://github.com/sigstore/cosign/pull/1491)
* Merge pull request from GHSA-ccxc-vr6p-4858
* fix(sign): refactor unsupported provider log (https://github.com/sigstore/cosign/pull/1464)
* Print message when verifying with old TUF targets (https://github.com/sigstore/cosign/pull/1468)
* convert release cosigned to also generate yaml artifact. (https://github.com/sigstore/cosign/pull/1453)
* Streamline `SignBlobCmd` API with `SignCmd` (https://github.com/sigstore/cosign/pull/1454)
* feat: add -buildid= to ldflags (https://github.com/sigstore/cosign/pull/1451)
* Fetch verification targets by TUF custom metadata (https://github.com/sigstore/cosign/pull/1423)
* feat: fig autocomplete feature (https://github.com/sigstore/cosign/pull/1360)
* Improve log lines to match with implementation (https://github.com/sigstore/cosign/pull/1432)
* use the upstream kubernetes version lib and ldflags (https://github.com/sigstore/cosign/pull/1413)
* feat: enhance clean cmd capability (https://github.com/sigstore/cosign/pull/1430)
* Remove TUF timestamp from OCI signature bundle (https://github.com/sigstore/cosign/pull/1428)
* Allow `PassFunc` to be `nil` (https://github.com/sigstore/cosign/pull/1426)
* Add ability to override the Spiffe socket via environmental variable: (https://github.com/sigstore/cosign/pull/1421)
* Improve error message when image is not found in registry (https://github.com/sigstore/cosign/pull/1410)
* add root status output (https://github.com/sigstore/cosign/pull/1404)
* feat: login command (https://github.com/sigstore/cosign/pull/1398)
* Minor refactor to verify SCT and Rekor entry with multiple keys (https://github.com/sigstore/cosign/pull/1396)
* Add Cosign logo to README (https://github.com/sigstore/cosign/pull/1395)
* Add `--timeout` support to `sign` command (https://github.com/sigstore/cosign/pull/1379)

## Bug Fixes

* bug fix: import ed25519 keys and fix error handling (https://github.com/sigstore/cosign/pull/1518)
* Fix wording on attach attestation help (https://github.com/sigstore/cosign/pull/1480)
* fix(sign): kms unspported message (https://github.com/sigstore/cosign/pull/1475)
* Fix incorrect error check when verifying SCT (https://github.com/sigstore/cosign/pull/1422)
* make imageRef lowercase before parsing (https://github.com/sigstore/cosign/pull/1409)
* Add a new line after password input (https://github.com/sigstore/cosign/pull/1407)
* Fix comparison in replace option for attestation (https://github.com/sigstore/cosign/pull/1366)

## Documention

* Quay OCI Support in README (https://github.com/sigstore/cosign/pull/1539)
* feat: nominate Dentrax as codeowner (https://github.com/sigstore/cosign/pull/1492)
* add initial changelog for 1.5.2 (https://github.com/sigstore/cosign/pull/1483)
* fix tkn link in readme (https://github.com/sigstore/cosign/pull/1459)
* Add FEATURES.md and DEPRECATIONS.md (https://github.com/sigstore/cosign/pull/1429)
* Update the cosign keyless documentation to point to the GA release. (https://github.com/sigstore/cosign/pull/1427)
* Fix link for SECURITY.md (https://github.com/sigstore/cosign/pull/1399)

## Others

* Consistent parenthesis use in Makefile (https://github.com/sigstore/cosign/pull/1541)
* Bump github.com/xanzy/go-gitlab from 0.55.1 to 0.56.0 (https://github.com/sigstore/cosign/pull/1538)
* add rpm,deb and apks for cosign packages (https://github.com/sigstore/cosign/pull/1537)
* update github.com/hashicorp/vault/sdk, codegen and go module to 1.17 (https://github.com/sigstore/cosign/pull/1536)
* images: remove --bare flags that conflict with --base-import-paths (https://github.com/sigstore/cosign/pull/1533)
* Bump actions/checkout from 2 to 3 (https://github.com/sigstore/cosign/pull/1531)
* Add codecov as github action, set permissions to read content only (https://github.com/sigstore/cosign/pull/1530)
* Bump github.com/spiffe/go-spiffe/v2 from 2.0.0-beta.11 to 2.0.0-beta.12 (https://github.com/sigstore/cosign/pull/1528)
* Bump actions/setup-go from 2 to 3 (https://github.com/sigstore/cosign/pull/1527)
* Bump golangci/golangci-lint-action from 3.0.0 to 3.1.0 (https://github.com/sigstore/cosign/pull/1526)
* Bump mikefarah/yq from 4.20.2 to 4.21.1 (https://github.com/sigstore/cosign/pull/1525)
* Bump github.com/secure-systems-lab/go-securesystemslib (https://github.com/sigstore/cosign/pull/1524)
* chore(ci): add artifact hub support (https://github.com/sigstore/cosign/pull/1522)
* optimize codeql speed by using caching and tracing (https://github.com/sigstore/cosign/pull/1519)
* Bump golangci/golangci-lint-action from 2.5.2 to 3 (https://github.com/sigstore/cosign/pull/1516)
* Bump github/codeql-action from 1.1.2 to 1.1.3 (https://github.com/sigstore/cosign/pull/1512)
* Bump mikefarah/yq from 4.16.2 to 4.20.2 (https://github.com/sigstore/cosign/pull/1510)
* Bump github.com/go-openapi/runtime from 0.23.0 to 0.23.1 (https://github.com/sigstore/cosign/pull/1507)
* Bump go.uber.org/zap from 1.20.0 to 1.21.0 (https://github.com/sigstore/cosign/pull/1509)
* Bump actions/setup-go from 2.1.5 to 2.2.0 (https://github.com/sigstore/cosign/pull/1495)
* Bump google-github-actions/auth from 0.4.4 to 0.6.0 (https://github.com/sigstore/cosign/pull/1501)
* Bump ossf/scorecard-action (https://github.com/sigstore/cosign/pull/1502)
* Bump google.golang.org/api from 0.69.0 to 0.70.0 (https://github.com/sigstore/cosign/pull/1500)
* Bump sigstore/cosign-installer from 1.4.1 to 2.0.1 (https://github.com/sigstore/cosign/pull/1496)
* Bump actions/github-script from 4.1.1 to 6 (https://github.com/sigstore/cosign/pull/1497)
* Update github/codeql-action requirement to d39d5d5c9707b926d517b1b292905ef4c03aa777 (https://github.com/sigstore/cosign/pull/1498)
* Bump google-github-actions/setup-gcloud from 0.3.0 to 0.5.1 (https://github.com/sigstore/cosign/pull/1499)
* chore(makefile): use kocache, convert publish to build (https://github.com/sigstore/cosign/pull/1488)
* Bump cloud.google.com/go/storage from 1.20.0 to 1.21.0 (https://github.com/sigstore/cosign/pull/1481)
* update changelog (https://github.com/sigstore/cosign/pull/1485)
* fix lint (https://github.com/sigstore/cosign/pull/1484)
* update go-tuf and simplify TUF client code (https://github.com/sigstore/cosign/pull/1455)
* Bump sigstore/sigstore to pick up the kms change and the monkey-patch work. (https://github.com/sigstore/cosign/pull/1479)
* refactor release cloudbuild job (https://github.com/sigstore/cosign/pull/1476)
* increase timeout for goreleaser snapshot (https://github.com/sigstore/cosign/pull/1473)
* Double goreleaser timeout (https://github.com/sigstore/cosign/pull/1472)
* Bump google.golang.org/api from 0.68.0 to 0.69.0 (https://github.com/sigstore/cosign/pull/1469)
* tests: `/bin/bash` -> `/usr/bin/env bash` (https://github.com/sigstore/cosign/pull/1470)
* Bump the gitlab library and add a nil opt for the API change. (https://github.com/sigstore/cosign/pull/1466)
* Bump webhook timeout. (https://github.com/sigstore/cosign/pull/1465)
* update cross-build to use go 1.17.7 (https://github.com/sigstore/cosign/pull/1446)
* Bump go-containerregistry, pick up new features (https://github.com/sigstore/cosign/pull/1442)
* update cross-build image which adds goimports (https://github.com/sigstore/cosign/pull/1435)
* Bump google.golang.org/api from 0.67.0 to 0.68.0 (https://github.com/sigstore/cosign/pull/1434)
* Skip the ReadWrite test that flakes on Windows. (https://github.com/sigstore/cosign/pull/1415)
* Bump github.com/go-openapi/strfmt from 0.21.1 to 0.21.2 (https://github.com/sigstore/cosign/pull/1411)
* Bump github.com/go-openapi/runtime from 0.22.0 to 0.23.0 (https://github.com/sigstore/cosign/pull/1412)
* Bump cloud.google.com/go/storage from 1.19.0 to 1.20.0 (https://github.com/sigstore/cosign/pull/1403)
* Bump google.golang.org/api from 0.66.0 to 0.67.0 (https://github.com/sigstore/cosign/pull/1402)
* Bump cuelang.org/go from 0.4.1 to 0.4.2 (https://github.com/sigstore/cosign/pull/1401)
* update cosign and cross-build image for the release job (https://github.com/sigstore/cosign/pull/1400)
* Bump github.com/xanzy/go-gitlab from 0.54.3 to 0.54.4 (https://github.com/sigstore/cosign/pull/1391)
* Bump github.com/go-openapi/swag from 0.20.0 to 0.21.1 (https://github.com/sigstore/cosign/pull/1386)
* Fix double `time` import in e2e tests (https://github.com/sigstore/cosign/pull/1388)
* Bump github.com/go-openapi/swag from 0.19.15 to 0.20.0 (https://github.com/sigstore/cosign/pull/1383)
* Bump github.com/go-openapi/runtime from 0.21.1 to 0.22.0 (https://github.com/sigstore/cosign/pull/1382)
* add changelog for 1.5.1 release (https://github.com/sigstore/cosign/pull/1376)

## Contributors

* Andrew Block (@sabre1041)
* Asra Ali (@asraa)
* Batuhan Apaydın (@developer-guy)
* Blake Burkhart (@bburky)
* Bob Callaway (@bobcallaway)
* Carlos Tadeu Panato Junior (@cpanato)
* Christian Kotzbauer (@ckotzbauer)
* Christopher Angelo Phillips (@spiffcs)
* Dan Lorenc (@dlorenc)
* Dan Luhring (@luhring)
* Furkan Türkal (@Dentrax)
* Hayden Blauzvern (@haydentherapper)
* Jason Hall (@imjasonh)
* Josh Dolitsky (@jdolitsky)
* Kenny Leung (@k4leung4)
* Matt Moore (@mattmoor)
* Marco Franssen (@marcofranssen)
* Nathan Smith (@nsmith5)
* Priya Wadhwa (@priyawadhwa)
* Sascha Grunert (@saschagrunert)
* Scott Nichols (@n3wscott)
* Teppei Fukuda (@knqyf263)
* Ville Aikas (@vaikas)
* Yongxuan Zhang (@Yongxuanzhang)
* Zack Newman (@znewman01)

# v1.5.2

## Security Fixes

* CVE-2022-23649 - Make sure signature in Rekor bundle matches signature being verified

## Others

* refactor release cloudbuild job (https://github.com/sigstore/cosign/pull/1476)
* increase timeout for goreleaser snapshot (https://github.com/sigstore/cosign/pull/1473)
* Double goreleaser timeout (https://github.com/sigstore/cosign/pull/1472)
* Bump webhook timeout. (https://github.com/sigstore/cosign/pull/1465)
* convert release cosigned to also generate yaml artifact. (https://github.com/sigstore/cosign/pull/1453)
* feat: add -buildid= to ldflags (https://github.com/sigstore/cosign/pull/1451)
* update cross-build to use go 1.17.7 (https://github.com/sigstore/cosign/pull/1446)

## Contributors

* Batuhan Apaydın (@developer-guy)
* Carlos Tadeu Panato Junior (@cpanato)
* Dan Lorenc (@dlorenc)
* Kenny Leung (@k4leung4)
* Matt Moore (@mattmoor)
* Nathan Smith (@nsmith5)
* Priya Wadhwa (@priyawadhwa)
* Zack Newman (@znewman01)

# v1.5.1

## Bug Fixes

* add check to make sure the go modules are in sync (https://github.com/sigstore/cosign/pull/1369)
* Update verify-blob to support DSSEs (https://github.com/sigstore/cosign/pull/1355)

## Documention

* docs: verify-attestation cue and rego policy doc (https://github.com/sigstore/cosign/pull/1362)
* README: fix link to race conditions (https://github.com/sigstore/cosign/pull/1367)

## Others

* Bump sigstore/sigstore to pick up oidc login for vault. (https://github.com/sigstore/cosign/pull/1377)
* Bump google.golang.org/api from 0.65.0 to 0.66.0 (https://github.com/sigstore/cosign/pull/1371)
* expose dafaults fulcio, rekor, oidc issuer urls (https://github.com/sigstore/cosign/pull/1368)
* Bump cloud.google.com/go/storage from 1.18.2 to 1.19.0 (https://github.com/sigstore/cosign/pull/1365)
* organize, update select deps (https://github.com/sigstore/cosign/pull/1358)
* Bump go-containerregistry to pick up ACR keychain fix (https://github.com/sigstore/cosign/pull/1357)
* Bump github.com/go-openapi/runtime from 0.21.0 to 0.21.1 (https://github.com/sigstore/cosign/pull/1352)
* sync go modules (https://github.com/sigstore/cosign/pull/1353)

## Contributors

* Batuhan Apaydın (@developer-guy)
* Carlos Tadeu Panato Junior (@cpanato)
* Dan Lorenc (@dlorenc)
* Jake Sanders (@dekkagaijin)
* Jason Hall (@imjasonh)
* Mark Lodato (@MarkLodato)
* Rémy Greinhofer (@rgreinho)

# v1.5.0

## Highlights

* enable sbom generation when releasing (https://github.com/sigstore/cosign/pull/1261)
* feat: log error to stderr (https://github.com/sigstore/cosign/pull/1260)
* feat: support attach attestation (https://github.com/sigstore/cosign/pull/1253)
* feat: resolve --cert from URL (https://github.com/sigstore/cosign/pull/1245)
* feat: generate/upload sbom for cosign projects (https://github.com/sigstore/cosign/pull/1237)
* feat: vuln attest support (https://github.com/sigstore/cosign/pull/1168)
* feat: add ambient credential detection with spiffe/spire (https://github.com/sigstore/cosign/pull/1220)
* feat: generate/upload sbom for cosign projects (https://github.com/sigstore/cosign/pull/1236)
* feat: implement cosign download attestation (https://github.com/sigstore/cosign/pull/1216)

## Enhancements

* Don't use k8schain, statically link cloud cred helpers in cosign (https://github.com/sigstore/cosign/pull/1279)
* Export function to verify individual signature (https://github.com/sigstore/cosign/pull/1334)
* Add suffix with digest to signature file output for recursive signing (https://github.com/sigstore/cosign/pull/1267)
* Take OIDC client secret into account (https://github.com/sigstore/cosign/pull/1310)
* Add --bundle flag to sign-blob and verify-blob (https://github.com/sigstore/cosign/pull/1306)
* Add flag to verify OIDC issuer in certificate (https://github.com/sigstore/cosign/pull/1308)
* add OSSF scorecard action (https://github.com/sigstore/cosign/pull/1318)
* Add TUF timestamp to attestation bundle (https://github.com/sigstore/cosign/pull/1316)
* Provide certificate flags to all verify commands (https://github.com/sigstore/cosign/pull/1305)
* Bundle TUF timestamp with signature on signing (https://github.com/sigstore/cosign/pull/1294)
* Add support for importing PKCShttps://github.com/sigstore/cosign/pull/8 private keys, and add validation (https://github.com/sigstore/cosign/pull/1300)
* add error message (https://github.com/sigstore/cosign/pull/1296)
* Move bundle out of `oci` and into `bundle` package (https://github.com/sigstore/cosign/pull/1295)
* Reorganize verify-blob code and add a unit test (https://github.com/sigstore/cosign/pull/1286)
* One-to-one mapping of invocation to scan result (https://github.com/sigstore/cosign/pull/1268)
* refactor common utilities (https://github.com/sigstore/cosign/pull/1266)
* Importing RSA and EC keypairs (https://github.com/sigstore/cosign/pull/1050)
* Refactor the tuf client code. (https://github.com/sigstore/cosign/pull/1252)
* Moved certificate output before checking for upload during signing (https://github.com/sigstore/cosign/pull/1255)
* Remove remaining ioutil usage (https://github.com/sigstore/cosign/pull/1256)
* Update the embedded TUF metadata. (https://github.com/sigstore/cosign/pull/1251)
* Add support for other public key types for SCT verification, allow override for testing. (https://github.com/sigstore/cosign/pull/1241)
* Log the proper remote repo for the signatures on verify (https://github.com/sigstore/cosign/pull/1243)
* Do not require multiple Fulcio certs in the TUF root (https://github.com/sigstore/cosign/pull/1230)
* clean up references to 'keyless' in `ephemeral.Signer` (https://github.com/sigstore/cosign/pull/1225)
* create `DSSEAttestor` interface, `payload.DSSEAttestor` implementation (https://github.com/sigstore/cosign/pull/1221)
* use `mutate.Signature` in the new `Signer`s (https://github.com/sigstore/cosign/pull/1213)
* create `mutate` functions for `oci.Signature` (https://github.com/sigstore/cosign/pull/1199)
* add a writeable `$HOME` for the `nonroot` cosigned user (https://github.com/sigstore/cosign/pull/1209)
* signing attestation should private key (https://github.com/sigstore/cosign/pull/1200)
* Remove the "upload" flag for "cosign initialize" (https://github.com/sigstore/cosign/pull/1201)
* create KeylessSigner (https://github.com/sigstore/cosign/pull/1189)

## Bug Fixes

* fix: cosign verify for vault (https://github.com/sigstore/cosign/pull/1328)
* fix missing goimports (https://github.com/sigstore/cosign/pull/1327)
* Fix TestSignBlobBundle (https://github.com/sigstore/cosign/pull/1320)
* Fix a couple bugs in cert verification for blobs (https://github.com/sigstore/cosign/pull/1287)
* Fix a few bugs in cosign initialize (https://github.com/sigstore/cosign/pull/1280)
* Fix the unit tests with expired TUF metadata. (https://github.com/sigstore/cosign/pull/1270)
* Fix output-file flag. (https://github.com/sigstore/cosign/pull/1264)
* fix: typo in the error message (https://github.com/sigstore/cosign/pull/1250)
* Fix semantic bugs in attestation verifification. (https://github.com/sigstore/cosign/pull/1249)
* Fix semantic bug in DSSE specification. (https://github.com/sigstore/cosign/pull/1248)

## Others

* Bump github.com/google/go-cmp from 0.5.6 to 0.5.7 (https://github.com/sigstore/cosign/pull/1343)
* Bump recommended Go development version in README (https://github.com/sigstore/cosign/pull/1340)
* Bump the snapshot and timestamp roles metadata from root signing. (https://github.com/sigstore/cosign/pull/1339)
* Bump github.com/spiffe/go-spiffe/v2 from 2.0.0-beta.10 to 2.0.0-beta.11 (https://github.com/sigstore/cosign/pull/1336)
* update go-github to v42 release (https://github.com/sigstore/cosign/pull/1335)
* install latest release for ko instead of head of main branch (https://github.com/sigstore/cosign/pull/1333)
* remove wrong settings in the gco auth for gh actions (https://github.com/sigstore/cosign/pull/1332)
* update gcp setup for the GH action (https://github.com/sigstore/cosign/pull/1330)
* update some dependencies (https://github.com/sigstore/cosign/pull/1326)
* Verify checksum of downloaded utilities during CI (https://github.com/sigstore/cosign/pull/1322)
* pin github actions by digest (https://github.com/sigstore/cosign/pull/1319)
* Bump google.golang.org/api from 0.64.0 to 0.65.0 (https://github.com/sigstore/cosign/pull/1303)
* Bump cuelang.org/go from 0.4.0 to 0.4.1 (https://github.com/sigstore/cosign/pull/1302)
* Bump github.com/xanzy/go-gitlab from 0.54.2 to 0.54.3 (https://github.com/sigstore/cosign/pull/1292)
* update import documentation (https://github.com/sigstore/cosign/pull/1290)
* update release image to use go 1.17.6 (https://github.com/sigstore/cosign/pull/1284)
* Bump google.golang.org/api. (https://github.com/sigstore/cosign/pull/1283)
* Bump opa and go-gitlab. (https://github.com/sigstore/cosign/pull/1281)
* Update SBOM spec to indicate compat for syft (https://github.com/sigstore/cosign/pull/1278)
* Bump miekg/pkcs11 (https://github.com/sigstore/cosign/pull/1275)
* Update signature spec with timestamp annotation (https://github.com/sigstore/cosign/pull/1274)
* Pick up latest knative.dev/pkg, and k8s 0.22 libs (https://github.com/sigstore/cosign/pull/1269)
* Bump sigstore/sigstore. (https://github.com/sigstore/cosign/pull/1247)
* Spelling (https://github.com/sigstore/cosign/pull/1246)
* Use ${{github.repository}} placeholder in OIDC GitHub workflow (https://github.com/sigstore/cosign/pull/1244)
* update codeowners list with missing codeowners (https://github.com/sigstore/cosign/pull/1238)
* update build images for release and bump cosign in the release job (https://github.com/sigstore/cosign/pull/1234)
* update deps (https://github.com/sigstore/cosign/pull/1222)
* nit: add comments to `Signer` interface (https://github.com/sigstore/cosign/pull/1228)
* update google.golang.org/api from 0.62.0 to 0.63.0 (https://github.com/sigstore/cosign/pull/1214)
* update snapshot and timestamp (https://github.com/sigstore/cosign/pull/1211)
* Bump github.com/spf13/viper from 1.9.0 to 1.10.0 (https://github.com/sigstore/cosign/pull/1198)
* Bump the DSSE library and handle manual changes in the API. (https://github.com/sigstore/cosign/pull/1191)
* nit: drop every section title down a level (https://github.com/sigstore/cosign/pull/1188)

## Contributors

* Andrew Block (@sabre1041)
* Asra Ali (@asraa)
* Batuhan Apaydın (@developer-guy)
* Bob Callaway (@bobcallaway)
* Carlos Alexandro Becker (@caarlos0)
* Carlos Tadeu Panato Junior (@cpanato)
* Dan Lorenc (@dlorenc)
* Hayden Blauzvern (@haydentherapper)
* Hector Fernandez (@hectorj2f)
* Itxaka (@Itxaka)
* Ivan Wallis (@venafi-iw)
* Jake Sanders (@dekkagaijin)
* Jason Hall (@imjasonh)
* Josh Dolitsky (@jdolitsky)
* Josh Soref (@jsoref)
* Matt Moore (@mattmoor)
* Morten Linderud (@Foxboron)
* Priya Wadhwa (@priyawadhwa)
* Radoslav Gerganov (@rgerganov)
* Rob Best (@ribbybibby)
* Sambhav Kothari (@samj1912)
* Ville Aikas (@vaikas)
* Zack Newman (@znewman01)

# v1.4.1

## Highlights

A whole buncha bugfixes!

## Enhancements

* Files created with `--output-signature` and `--output-certificate` now created with 0600 permissions (https://github.com/sigstore/cosign/pull/1151)
* Added `cosign verify-attestation --local-image` for verifying signed images with attestations from disk (https://github.com/sigstore/cosign/pull/1174)
* Added the ability to fetch the TUF root over HTTP with `cosign initialize --mirror` (https://github.com/sigstore/cosign/pull/1185)

## Bug Fixes

* Fixed saving and loading a signed image index to disk (https://github.com/sigstore/cosign/pull/1147)
* Fixed `sign-blob --output-certificate` writing an empty file (https://github.com/sigstore/cosign/pull/1149)
* Fixed assorted issues related to the initialization and use of Sigstore's TUF root of trust (https://github.com/sigstore/cosign/pull/1157)

## Contributors

* Carlos Alexandro Becker (@caarlos0)
* Carlos Panato (@cpanato)
* Hayden Blauzvern (@haydentherapper)
* Jake Sanders (@dekkagaijin)
* Matt Moore (@mattmoor)
* Priya Wadhwa (@priyawadhwa)
* Radoslav Gerganov (@rgerganov)

# v1.4.0

## Highlights

* BREAKING [COSIGN_EXPERIMENTAL]: This and future `cosign` releases will generate signatures that do not validate in older versions of `cosign`. This only applies to "keyless" experimental mode. To opt out of this behavior, use: `--fulcio-url=https://fulcio.sigstore.dev` when signing payloads (https://github.com/sigstore/cosign/pull/1127)
* BREAKING [cosign/pkg]: `SignedEntryTimestamp` is now of type `[]byte`. To get the previous behavior, call `strfmt.Base64(SignedEntryTimestamp)` (https://github.com/sigstore/cosign/pull/1083)
* `cosign-linux-pivkey-amd64` releases are now of the form `cosign-linux-pivkey-pkcs11key-amd64` (https://github.com/sigstore/cosign/pull/1052)
* Releases are now additionally signed using the keyless workflow (https://github.com/sigstore/cosign/pull/1073, https://github.com/sigstore/cosign/pull/1111)

## Enhancements

* Validate the whole attestation statement, not just the predicate (https://github.com/sigstore/cosign/pull/1035)
* Added the options to replace attestations using `cosign attest --replace` (https://github.com/sigstore/cosign/pull/1039)
* Added URI to `cosign verify-blob` output (https://github.com/sigstore/cosign/pull/1047)
* Signatures and certificates created by `cosign sign` and `cosign sign-blob` can be output to file using the `--output-signature` and `--output-certificate` flags, respectively (https://github.com/sigstore/cosign/pull/1016, https://github.com/sigstore/cosign/pull/1093, https://github.com/sigstore/cosign/pull/1066, https://github.com/sigstore/cosign/pull/1095)
* [cosign/pkg] Added the `pkg/oci/layout` package for storing signatures and attestations on disk (https://github.com/sigstore/cosign/pull/1040, https://github.com/sigstore/cosign/pull/1096)
* [cosign/pkg] Added `mutate` methods to attach `oci.File`s to `oci.Signed*` objects (https://github.com/sigstore/cosign/pull/1084)
* Added the `--signature-digest-algorithm` flag to `cosign verify`, allowing verification of container image signatures which were generated with a non-SHA256 signature algorithm (https://github.com/sigstore/cosign/pull/1071)
* Builds should now be reproducible (https://github.com/sigstore/cosign/pull/1053)
* Allows base64 files as `--cert` in `cosign verify-blob` (https://github.com/sigstore/cosign/pull/1088)
* Kubernetes secrets generated for version >= 1.21 clusters have the immutable bit set (https://github.com/sigstore/cosign/pull/1091)
* Added `cosign save` and `cosign load` commands to save and upload container images and associated signatures to disk (https://github.com/sigstore/cosign/pull/1094)
* `cosign sign` will no longer fail to sign private images in keyless mode without `--force` (https://github.com/sigstore/cosign/pull/1116)
* `cosign verify` now supports signatures stored in files and remote URLs with `--signature` (https://github.com/sigstore/cosign/pull/1068)
* `cosign verify` now supports certs stored in files (https://github.com/sigstore/cosign/pull/1095)
* Added support for `syft` format in `cosign attach sbom` (https://github.com/sigstore/cosign/pull/1137)

## Bug Fixes

* Fixed verification of Rekor bundles for InToto attestations (https://github.com/sigstore/cosign/pull/1030)
* Fixed a potential memory leak when signing and verifying with security keys (https://github.com/sigstore/cosign/pull/1113)

## Contributors

* Ashley Davis (@SgtCoDFish)
* Asra Ali (@asraa)
* Batuhan Apaydın (@developer-guy)
* Brandon Philips (@philips)
* Carlos Alexandro Becker (@caarlos0)
* Carlos Panato (@cpanato)
* Christian Rebischke (@shibumi)
* Dan Lorenc (@dlorenc)
* Erkan Zileli (@erkanzileli)
* Furkan Türkal (@Dentrax)
* garantir-km (@garantir-km)
* Jake Sanders (@dekkagaijin)
* jbpratt (@jbpratt)
* Matt Moore (@mattmoor)
* Mikey Strauss (@houdini91)
* Naveen Srinivasan (@naveensrinivasan)
* Priya Wadhwa (@priyawadhwa)
* Sambhav Kothari (@samj1912)

# v1.3.1

* BREAKING [cosign/pkg]: `cosign.Verify` has been removed in favor of explicit `cosign.VerifyImageSignatures` and `cosign.VerifyImageAttestations`
 (https://github.com/sigstore/cosign/pull/1026)

## Enhancements

* Add ability for verify-blob to find signing cert in transparency log (https://github.com/sigstore/cosign/pull/991)
* root policy: add optional issuer to maintainer keys (https://github.com/sigstore/cosign/pull/999)
* PKCS11 signing support (https://github.com/sigstore/cosign/pull/985)
* Included timeout option for uploading to Rekor (https://github.com/sigstore/cosign/pull/1001)

## Bug Fixes

* Bump sigstore/sigstore to pickup a fix for azure kms (https://github.com/sigstore/cosign/pull/1011 / https://github.com/sigstore/cosign/pull/1028)

## Contributors

* Asra Ali (@asraa)
* Batuhan Apaydın (@developer-guy)
* Carlos Panato (@cpanato)
* Dan Lorenc (@dlorenc)
* Dennis Leon (@DennisDenuto)
* Erkan Zileli (@erkanzileli)
* Furkan Türkal (@Dentrax)
* garantir-km (@garantir-km)
* Jake Sanders (@dekkagaijin)
* Naveen (@naveensrinivasan)

# v1.3.0

* BREAKING: `verify-manifest` is now `manifest verify` (https://github.com/sigstore/cosign/pull/712)
* BREAKING: `/pkg` has been heavily refactored. [Further refactoring work](https://github.com/sigstore/cosign/issues/844) will make its way into 1.4.0
* WARNING: The CLI now uses POSIX-style (double-dash `--flag`) for long-form flags. It will temporarily accept the single-dash `-flag` form with a warning, which will become an error in a future release (https://github.com/sigstore/cosign/pull/835)
* Added `sget` as part of Cosign's releases (https://github.com/sigstore/cosign/pull/752)
* The `copasetic` utility was unceremoniously [baleeted](https://www.youtube.com/watch?v=07h0ksKx5sM) (https://github.com/sigstore/cosign/pull/785)

## Enhancements

* Began reworking `/pkg` around new abstractions for signing, verification, and storage (https://github.com/sigstore/cosign/issues/666)
    * Notice: refactoring of `/pkg` will continue in the next minor release (1.4.0). Please leave feedback, especially if you've been experimenting with `cosign` as a library and found it lacking (https://github.com/sigstore/cosign/issues/844)
    * [GGCR-style libraries](https://github.com/google/go-containerregistry#philosophy) for interacting with images now exist under `pkg/oci` (https://github.com/sigstore/cosign/pull/770)
    * `pkg/cosign/remote.UploadSignature` API was been removed in favor of new `pkg/oci/remote` APIs (https://github.com/sigstore/cosign/pull/774)
    * The function signature of `cosign.Verify` was changed so that callers must be explicit about which signatures (or attestations) to verify. For matching signatures, see also `cosign.Verify{Signatures,Attestations}` (https://github.com/sigstore/cosign/pull/782)
    * Removed `cremote.UploadFile` in favor of `static.NewFile` and `remote.Write` (https://github.com/sigstore/cosign/pull/797)
* Innumerable other improvements to the codebase and automation ([Makin me look bad, @mattmoor](https://github.com/sigstore/cosign/commits?author=mattmoor))
* Migrated the CLI to `cobra` ([Welcome to the team, @n3wscott](https://github.com/sigstore/cosign/commits?author=n3wscott))
* Added the `--allow-insecure-registry` flag to disable TLS verification when interacting with insecure (e.g. self-signed) container registries (https://github.com/sigstore/cosign/pull/669)
* 🔒 `cosigned` now includes a mutating webhook that resolves image tags to digests (https://github.com/sigstore/cosign/pull/800)
* 🔒 The `cosigned` validating webhook now requires image digest references (https://github.com/sigstore/cosign/pull/799)
* The `cosigned` webhook now ignores resources that are being deleted (https://github.com/sigstore/cosign/pull/803)
* The `cosigned` webhook now supports resolving private images that are authenticated via `imagePullSecrets` (https://github.com/sigstore/cosign/pull/804)
* `manifest verify` now supports verifying images in all Kubernetes objects that fit within `PodSpec`, `PodSpecTemplate`, or `JobSpecTemplate`, including CRDs (https://github.com/sigstore/cosign/pull/697)
* Added shell auto-completion support (Clutch collab from @erkanzileli, @passcod, and @Dentrax! https://github.com/sigstore/cosign/pull/836)
* `cosign` has generated Markdown docs available in the `doc/` directory (https://github.com/sigstore/cosign/pull/839)
* Added support for verifying with secrets from a GitLab project (https://github.com/sigstore/cosign/pull/934)
* Added a `--k8s-keychain` option that enables cosign to support ambient registry credentials based on the "k8schain" library (https://github.com/sigstore/cosign/pull/972)
* CI (test) Images are now created for every architecture distroless ships on (currently: amd64, arm64, arm, s390x, ppc64le) (https://github.com/sigstore/cosign/pull/973)
* `attest`: replaced `--upload` flag with a `--no-upload` flag (https://github.com/sigstore/cosign/pull/979)

## Bug Fixes

* `cosigned` now verifies `CronJob` images (Terve, @vaikas https://github.com/sigstore/cosign/pull/809)
* Fixed the `verify` `--cert-email` option to actually work (Sweet as, @passcod https://github.com/sigstore/cosign/pull/821)
* `public-key -sk` no longer causes  `error: x509: unsupported public key type: *crypto.PublicKey` (https://github.com/sigstore/cosign/pull/864)
* Fixed interactive terminal support in Windows (https://github.com/sigstore/cosign/pull/871)
* The `-ct` flag is no longer ignored in `upload blob` (https://github.com/sigstore/cosign/pull/910)

## Contributors

* Aditya Sirish (@adityasaky)
* Asra Ali (@asraa)
* Axel Simon (@axelsimon)
* Batuhan Apaydın (@developer-guy)
* Brandon Mitchell (@sudo-bmitch)
* Carlos Panato (@cpanato)
* Chao Lin (@blackcat-lin)
* Dan Lorenc (@dlorenc)
* Dan Luhring (@luhring)
* Eng Zer Jun (@Juneezee)
* Erkan Zileli (@erkanzileli)
* Félix Saparelli (@passcod)
* Furkan Türkal (@Dentrax)
* Hector Fernandez (@hectorj2f)
* Ivan Font (@font)
* Jake Sanders (@dekkagaijin)
* Jason Hall (@imjasonh)
* Jim Bugwadia (@JimBugwadia)
* Joel Kamp (@mrjoelkamp)
* Luke Hinds (@lukehinds)
* Matt Moore (@mattmoor)
* Naveen (@naveensrinivasan)
* Olivier Gaumond (@oliviergaumond)
* Priya Wadhwa (@priyawadhwa)
* Radoslav Gerganov (@rgerganov)
* Ramkumar Chinchani (@rchincha)
* Rémy Greinhofer (@rgreinho)
* Scott Nichols (@n3wscott)
* Shubham Palriwala (@ShubhamPalriwala)
* Viacheslav Vasilyev (@avoidik)
* Ville Aikas (@vaikas)

# v1.2.0

## Enhancements
* BREAKING: move `verify-dockerfile` to `dockerfile verify` (https://github.com/sigstore/cosign/pull/662)
* Have the keyless `cosign sign` flow use a single 3LO. (https://github.com/sigstore/cosign/pull/665)
* Allow to `verify-blob` from urls (https://github.com/sigstore/cosign/pull/646)
* Support GCP environments without workload identity (GCB). (https://github.com/sigstore/cosign/pull/652)
* Switch the release cosign container to debug. (https://github.com/sigstore/cosign/pull/649)
* Add logic to detect and use ambient OIDC from exec envs. (https://github.com/sigstore/cosign/pull/644)
* Add `-cert-email` flag to provide the email expected from a fulcio cert to be valid (https://github.com/sigstore/cosign/pull/622)
* Add support for downloading signature from remote (https://github.com/sigstore/cosign/pull/629)
* Add sbom and attestations to triangulate (https://github.com/sigstore/cosign/pull/628)
* Add cosign attachment signing and verification (https://github.com/sigstore/cosign/pull/615)
* Embed CT log public key (https://github.com/sigstore/cosign/pull/607)
* Verify SCTs returned by fulcio (https://github.com/sigstore/cosign/pull/600)
* Add extra replacement variables and GCP's role identifier (https://github.com/sigstore/cosign/pull/597)
* Store attestations in the layer (payload) rather than the annotation. (https://github.com/sigstore/cosign/pull/579)
* Improve documentation about predicate type and change predicate type from provenance to slsaprovenance (https://github.com/sigstore/cosign/pull/583)
* Upgrade in-toto-golang to adapt SLSA Provenance (https://github.com/sigstore/cosign/pull/582)

## Bug Fixes
* Fix verify-dockerfile to allow lowercase FROM (https://github.com/sigstore/cosign/pull/643)
* Fix signing for the cosigned image. (https://github.com/sigstore/cosign/pull/634)
* Make sure generate-key-pair doesn't overwrite existing key-pair (https://github.com/sigstore/cosign/pull/623)
* helm/ci: update helm repo before installing the dependency (https://github.com/sigstore/cosign/pull/598)
* Set the correct predicate type/URI for each supported predicate type. (https://github.com/sigstore/cosign/pull/592)
* Warnings on admissionregistration version (https://github.com/sigstore/cosign/pull/581)
* Remove unnecessary COSIGN_PASSWORD (https://github.com/sigstore/cosign/pull/572)

## Contributors
* Batuhan Apaydın
* Ben Walding
* Carlos Alexandro Becker
* Carlos Tadeu Panato Junior
* Erkan Zileli
* Hector Fernandez
* Jake Sanders
* Jason Hall
* Matt Moore
* Michael Lieberman
* Naveen Srinivasan
* Pradeep Chhetri
* Sambhav Kothari
* dlorenc
* priyawadhwa


# v1.1.0

## Enhancements

* BREAKING: The `-attestation` flag has been renamed to `-predicate` in `attest` (https://github.com/sigstore/cosign/pull/500)
* Added `verify-manifest` command (https://github.com/sigstore/cosign/pull/490)
* Added the ability to specify and validate well-known attestation types in `attest` with the `-type` flag (https://github.com/sigstore/cosign/pull/504)
* Added `cosign init` command to setup the trusted local repository of SigStore's TUF root metadata (https://github.com/sigstore/cosign/pull/520)
* Added timestamps to Cosign's custom In-Toto predicate (https://github.com/sigstore/cosign/pull/533)
* `verify` now always verifies that the image exists (even when referenced by digest) before verification (https://github.com/sigstore/cosign/pull/543)

## Bug Fixes

* `verify-dockerfile` no longer fails on `FROM scratch` (https://github.com/sigstore/cosign/pull/509)
* Fixed reading from STDIN with `attach sbom` (https://github.com/sigstore/cosign/pull/517)
* Fixed broken documentation and implementation of `-output` for `verify` and `verify-attestation` (https://github.com/sigstore/cosign/pull/546)
* Fixed nil pointer error when calling `upload blob` without specifying `-f` (https://github.com/sigstore/cosign/pull/563)

## Contributors

* Adolfo García Veytia (@puerco)
* Anton Semjonov (@ansemjo)
* Asra Ali (@asraa)
* Batuhan Apaydın (@developer-guy)
* Carlos Panato (@cpanato)
* Dan Lorenc (@dlorenc)
* @gkovan
* Hector Fernandez (@hectorj2f)
* Jake Sanders (@dekkagaijin)
* Jim Bugwadia (@JimBugwadia)
* Jose Donizetti (@josedonizetti)
* Joshua Hansen (@joshes)
* Jason Hall (@imjasonh)
* Priya Wadhwa (@priyawadhwa)
* Russell Brown (@rjbrown57)
* Stephan Renatus (@srenatus)
* Li Yi (@denverdino)

# v1.0.0

## Enhancements

* BREAKING: The default HSM key slot is now "signature" instead of "authentication" (https://github.com/sigstore/cosign/pull/450)
* BREAKING: `--fulcio-server` is now `--fulcio-url` (https://github.com/sigstore/cosign/pull/471)
* Added `-cert` flag to `sign` to allow the explicit addition of a signature certificate (https://github.com/sigstore/cosign/pull/451)
* Added the `attest` command (https://github.com/sigstore/cosign/pull/458)
* Added numerous flags for specifying parameters when interacting with Rekor and Fulcio (https://github.com/sigstore/cosign/pull/462)
* `cosign` will now send its version string as part of the `user-agent` when interacting with a container registry (https://github.com/sigstore/cosign/pull/479)
* Files containing certificates for custom Fulcio endpoints can now be specified via the `COSIGN_ROOT` environment variable (https://github.com/sigstore/cosign/pull/477)

## Bug Fixes

* Fixed a situation where lower-case `as` would break `verify-dockerfile` (Complements to @Dentrax https://github.com/sigstore/cosign/pull/433)

## Contributors

* Appu Goundan (@loosebazooka)
* Batuhan Apaydın (@developer-guy)
* Carlos Panato (@cpanato)
* Dan Lorenc (@dlorenc)
* Furkan Türkal (@Dentrax)
* Hector Fernandez (@hectorj2f)
* Jake Sanders (@dekkagaijin)
* James Alseth (@jalseth)
* Jason Hall (@imjasonh)
* João Pereira (@joaodrp)
* Luke Hinds (@lukehinds)
* Tom Hennen (@TomHennen)

# v0.6.0

## Enhancements

* BREAKING: Moved `cosign upload-blob` to `cosign upload blob` (https://github.com/sigstore/cosign/pull/378)
* BREAKING: Moved `cosign upload` to `cosign attach signature` (https://github.com/sigstore/cosign/pull/378)
* BREAKING: Moved `cosign download` to `cosign download signature` (https://github.com/sigstore/cosign/pull/392)
* Added flags to specify slot, PIN, and touch policies for security keys (Thank you @ddz https://github.com/sigstore/cosign/pull/369)
* Added `cosign verify-dockerfile` command (https://github.com/sigstore/cosign/pull/395)
* Added SBOM support in `cosign attach` and `cosign download sbom` (https://github.com/sigstore/cosign/pull/387)
* Sign & verify images using Kubernetes secrets (A muchas muchas gracias to @developer-guy and @Dentrax https://github.com/sigstore/cosign/pull/398)
* Added support for AWS KMS (谢谢, @codysoyland https://github.com/sigstore/cosign/pull/426)
* Numerous enhancements to our build & release process, courtesy @cpanato

## Bug Fixes

* Verify entry timestamp signatures of fetched Tlog entries (https://github.com/sigstore/cosign/pull/371)

## Contributors

* Asra Ali (@asraa)
* Batuhan Apaydın (@developer-guy)
* Carlos Panato (@cpanato)
* Cody Soyland (@codysoyland)
* Dan Lorenc (@dlorenc)
* Dino A. Dai Zovi (@ddz)
* Furkan Türkal (@Dentrax)
* Jake Sanders (@dekkagaijin)
* Jason Hall (@imjasonh)
* Paris Zoumpouloglou (@zuBux)
* Priya Wadhwa (@priyawadhwa)
* Rémy Greinhofer (@rgreinho)
* Russell Brown (@rjbrown57)

# v0.5.0

## Enhancements

* Added `cosign copy` to easily move images and signatures between repositories (https://github.com/sigstore/cosign/pull/317)
* Added `-r` flag to `cosign sign` for recursively signing multi-arch images (https://github.com/sigstore/cosign/pull/320)
* Added `cosign clean` to delete signatures for an image (Thanks, @developer-guy! https://github.com/sigstore/cosign/pull/324)
* Added `-k8s` flag to `cosign generate-key-pair` to create a Kubernetes secret (Hell yeah, @priyawadhwa! https://github.com/sigstore/cosign/pull/345)

## Bug Fixes

* Fixed an issue with misdirected image signatures when `COSIGN_REPOSITORY` was used (https://github.com/sigstore/cosign/pull/323)

## Contributors

* Balazs Zachar (@Cajga)
* Batuhan Apaydın (@developer-guy)
* Dan Lorenc (@dlorenc)
* Furkan Turkal (@Dentrax)
* Jake Sanders (@dekkagaijin)
* Jon Johnson (@jonjohnsonjr)
* Priya Wadhwa (@priyawadhwa)

# v0.4.0

## Action Required

* Signatures created with `cosign` before v0.4.0 are not compatible with those created after
    * The signature image's manifest now uses OCI mediaTypes ([#300](https://github.com/sigstore/cosign/pull/300))
    * The signature image's tag is now terminated with `.sig` (instead of `.cosign`, [#287](https://github.com/sigstore/cosign/pull/287))

## Enhancements

* 🎉 Added support for "offline" verification of Rekor signatures 🎉 (ありがとう, priyawadhwa! [#285](https://github.com/sigstore/cosign/pull/285))
* Support for Hashicorp vault as a KMS provider has been added (Danke, RichiCoder1! [sigstore/sigstore #44](https://github.com/sigstore/sigstore/pull/44), [sigstore/sigstore #49](https://github.com/sigstore/sigstore/pull/44))

## Bug Fixes

* GCP KMS URIs now include the key version ([#45](https://github.com/sigstore/sigstore/pull/45))

## Contributors

* Christian Pearce (@pearcec)
* Dan Lorenc (@dlorenc)
* Jake Sanders (@dekkagaijin)
* Priya Wadhwa (@priyawadhwa)
* Richard Simpson (@RichiCoder1)
* Ross Timson (@rosstimson)

# v0.3.1

## Bug Fixes

* Fixed CI container image breakage introduced in v0.3.0
* Fixed lack of version information in release binaries

# v0.3.0

This is the third release of `cosign`!

We still expect many flags, commands, and formats to change going forward, but we're getting closer.
No backwards compatibility is promised or implied yet, though we are hoping to formalize this policy in the next release.
See [#254](https://github.com/sigstore/cosign/issues/254) for more info.

## Enhancements

* The `-output-file` flag supports writing output to a specific file
* The `-key` flag now supports `kms` references and URLs, the `kms` specific flag has been removed
* Yubikey/PIV hardware support is now included!
* Support for signing and verifying multiple images in one invocation

## Bug Fixes

* Bug fixes in KMS keypair generation
* Bug fixes in key type parsing

## Contributors

* Dan Lorenc
* Priya Wadhwa
* Ivan Font
* Dependabot!
* Mark Bestavros
* Jake Sanders
* Carlos Tadeu Panato Junior

# v0.2.0

This is the second release of `cosign`!

We still expect many flags, commands, and formats to change going forward, but we're getting closer.
No backwards compatibility is promised or implied.

## Enhancements

* The password for private keys can now be passed via the `COSIGN_PASSWORD`
* KMS keys can now be used to sign and verify blobs
* The `version` command can now be used to return the release version
* The `public-key` command can now be used to extract the public key from KMS or a private key
* The `COSIGN_REPOSITORY` environment variable can be used to store signatures in an alternate location
* Tons of new EXAMPLES in our help text

## Bug Fixes

* Improved error messages for command line flag verification
* TONS more unit and integration testing
* Too many others to count :)

## Contributors

We would love to thank the contributors:

* Dan Lorenc
* Priya Wadhwa
* Ahmet Alp Balkan
* Naveen Srinivasan
* Chris Norman
* Jon Johnson
* Kim Lewandowski
* Luke Hinds
* Bob Callaway
* Dan POP
* eminks
* Mark Bestavros
* Jake Sanders

# v0.1.0

This is the first release of `cosign`!

The main goal of this release is to release something we can start using to sign other releases of [sigstore](sigstore.dev) projects, including `cosign` itself.

We expect many flags, commands, and formats to change going forward.
No backwards compatibility is promised or implied.

## Enhancements

This release added a feature to `cosign` called `cosign`.
The `cosign` feature can be used to sign container images and blobs.
Detailed documentation can be found in the [README](README.md) and the [Detailed Usage](USAGE.md).

## Bug Fixes

There was no way to sign container images. Now there is!

## Contributors

We would love to thank the contributors:

* dlorenc
* priyawadhwa
* Ahmet Alp Balkan
* Ivan Font
* Jason Hall
* Chris Norman
* Jon Johnson
* Kim Lewandowski
* Luke Hinds
* Bob Callaway
