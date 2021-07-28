# Changelog

## v1.0.0

### Enhancements

* BREAKING: The default HSM key slot is now "signature" instead of "authentication" (https://github.com/sigstore/cosign/pull/450)
* BREAKING: `--fulcio-server` is now `--fulcio-url` (https://github.com/sigstore/cosign/pull/471)
* Added `-cert` flag to `sign` to allow the explicit addition of a signature certificate (https://github.com/sigstore/cosign/pull/451)
* Added the `attest` command (https://github.com/sigstore/cosign/pull/458)
* Added numerous flags for specifying parameters when interacting with Rekor and Fulcio (https://github.com/sigstore/cosign/pull/462)
* `cosign` will now send its version string as part of the `user-agent` when interacting with a container registry (https://github.com/sigstore/cosign/pull/479)
* Files containing certificates for custom Fulcio endpoints can now be specified via the `COSIGN_ROOT` environment variable (https://github.com/sigstore/cosign/pull/477)

### Bug Fixes

* Fixed a situation where lower-case `as` would break `verify-dockerfile` (Complements to @Dentrax https://github.com/sigstore/cosign/pull/433)

### Contributors

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

## v0.6.0

### Enhancements

* BREAKING: Moved `cosign upload-blob` to `cosign upload blob` (https://github.com/sigstore/cosign/pull/378)
* BREAKING: Moved `cosign upload` to `cosign attach signature` (https://github.com/sigstore/cosign/pull/378)
* BREAKING: Moved `cosign download` to `cosign download signature` (https://github.com/sigstore/cosign/pull/392)
* Added flags to specify slot, PIN, and touch policies for security keys (Thank you @ddz https://github.com/sigstore/cosign/pull/369)
* Added `cosign verify-dockerfile` command (https://github.com/sigstore/cosign/pull/395)
* Added SBOM support in `cosign attach` and `cosign download sbom` (https://github.com/sigstore/cosign/pull/387)
* Sign & verify images using Kubernetes secrets (A muchas muchas gracias to @developer-guy and @Dentrax https://github.com/sigstore/cosign/pull/398)
* Added support for AWS KMS (谢谢, @codysoyland https://github.com/sigstore/cosign/pull/426)
* Numerous enhancements to our build & release process, courtesy @cpanato

### Bug Fixes

* Verify entry timestamp signatures of fetched Tlog entries (https://github.com/sigstore/cosign/pull/371)

### Contributors

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

## v0.5.0

### Enhancements

* Added `cosign copy` to easily move images and signatures between repositories (https://github.com/sigstore/cosign/pull/317)
* Added `-r` flag to `cosign sign` for recursively signing multi-arch images (https://github.com/sigstore/cosign/pull/320)
* Added `cosign clean` to delete signatures for an image (Thanks, @developer-guy! https://github.com/sigstore/cosign/pull/324)
* Added `-k8s` flag to `cosign generate-key-pair` to create a Kubernetes secret (Hell yeah, @priyawadhwa! https://github.com/sigstore/cosign/pull/345)

### Bug Fixes

* Fixed an issue with misdirected image signatures when `COSIGN_REPOSITORY` was used (https://github.com/sigstore/cosign/pull/323)

### Contributors

* Balazs Zachar (@Cajga)
* Batuhan Apaydın (@developer-guy)
* Dan Lorenc (@dlorenc)
* Furkan Turkal (@Dentrax)
* Jake Sanders (@dekkagaijin)
* Jon Johnson (@jonjohnsonjr)
* Priya Wadhwa (@priyawadhwa)

## v0.4.0

### Action Required

* Signatures created with `cosign` before v0.4.0 are not compatible with those created after
    * The signature image's manifest now uses OCI mediaTypes ([#300](https://github.com/sigstore/cosign/pull/300))
    * The signature image's tag is now terminated with `.sig` (instead of `.cosign`, [#287](https://github.com/sigstore/cosign/pull/287))

### Enhancements

* 🎉 Added support for "offline" verification of Rekor signatures 🎉 (ありがとう, priyawadhwa! [#285](https://github.com/sigstore/cosign/pull/285))
* Support for Hashicorp vault as a KMS provider has been added (Danke, RichiCoder1! [sigstore/sigstore #44](https://github.com/sigstore/sigstore/pull/44), [sigstore/sigstore #49](https://github.com/sigstore/sigstore/pull/44))

### Bug Fixes

* GCP KMS URIs now include the key version ([#45](https://github.com/sigstore/sigstore/pull/45))

### Contributors

* Christian Pearce (@pearcec)
* Dan Lorenc (@dlorenc)
* Jake Sanders (@dekkagaijin)
* Priya Wadhwa (@priyawadhwa)
* Richard Simpson (@RichiCoder1)
* Ross Timson (@rosstimson)

## v0.3.1

### Bug Fixes

* Fixed CI container image breakage introduced in v0.3.0
* Fixed lack of version information in release binaries

## v0.3.0

This is the third release of `cosign`!

We still expect many flags, commands, and formats to change going forward, but we're getting closer.
No backwards compatiblity is promised or implied yet, though we are hoping to formalize this policy in the next release.
See [#254](https://github.com/sigstore/cosign/issues/254) for more info.

### Enhancements

* The `-output-file` flag supports writing output to a specific file
* The `-key` flag now supports `kms` references and URLs, the `kms` specific flag has been removed
* Yubikey/PIV hardware support is now included!
* Support for signing and verifying multiple images in one invocation

### Bug Fixes

* Bug fixes in KMS keypair generation
* Bug fixes in key type parsing

### Contributors

* Dan Lorenc
* Priya Wadhwa
* Ivan Font
* Depandabot!
* Mark Bestavros
* Jake Sanders
* Carlos Tadeu Panato Junior 

## v0.2.0

This is the second release of `cosign`!

We still expect many flags, commands, and formats to change going forward, but we're getting closer.
No backwards compatiblity is promised or implied.

### Enhancements

* The password for private keys can now be passed via the `COSIGN_PASSWORD`
* KMS keys can now be used to sign and verify blobs
* The `version` command can now be used to return the release version
* The `public-key` command can now be used to extract the public key from KMS or a private key
* The `COSIGN_REPOSITORY` environment variable can be used to store signatures in an alternate location
* Tons of new EXAMPLES in our help text

### Bug Fixes

* Improved error messages for command line flag verification
* TONS more unit and integration testing
* Too many others to count :)

### Contributors

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

## v0.1.0

This is the first release of `cosign`!

The main goal of this release is to release something we can start using to sign other releases of [sigstore](sigstore.dev) projects, including `cosign` itself.

We expect many flags, commands, and formats to change going forward.
No backwards compatiblity is promised or implied.

### Enhancements

This release added a feature to `cosign` called `cosign`.
The `cosign` feature can be used to sign container images and blobs.
Detailed documentation can be found in the [README](README.md) and the [Detailed Usage](USAGE.md).

### Bug Fixes

There was no way to sign container images. Now there is!

### Contributors

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
