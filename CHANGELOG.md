# Changelog

## v1.3.1

* BREAKING [cosign/pkg]: `cosign.Verify` has been removed in favor of explicit `cosign.VerifyImageSignatures` and `cosign.VerifyImageAttestations`
 (https://github.com/sigstore/cosign/pull/1026)

### Enhancements

* Add ability for verify-blob to find signing cert in transparency log (https://github.com/sigstore/cosign/pull/991)
* root policy: add optional issuer to maintainer keys (https://github.com/sigstore/cosign/pull/999)
* PKCS11 signing support (https://github.com/sigstore/cosign/pull/985)
* Included timeout option for uploading to Rekor (https://github.com/sigstore/cosign/pull/1001)

### Bug Fixes

* Bump sigstore/sigstore to pickup a fix for azure kms (https://github.com/sigstore/cosign/pull/1011 / https://github.com/sigstore/cosign/pull/1028)

### Contributors

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

## v1.3.0

* BREAKING: `verify-manifest` is now `manifest verify` (https://github.com/sigstore/cosign/pull/712)
* BREAKING: `/pkg` has been heavily refactored. [Further refactoring work](https://github.com/sigstore/cosign/issues/844) will make its way into 1.4.0
* WARNING: The CLI now uses POSIX-style (double-dash `--flag`) for long-form flags. It will temporarily accept the single-dash `-flag` form with a warning, which will become an error in a future release (https://github.com/sigstore/cosign/pull/835)
* Added `sget` as part of Cosign's releases (https://github.com/sigstore/cosign/pull/752)
* The `copasetic` utility was unceremoniously [baleeted](https://www.youtube.com/watch?v=07h0ksKx5sM) (https://github.com/sigstore/cosign/pull/785)

### Enhancements

* Began reworking `/pkg` around new abstrations for signing, verification, and storage (https://github.com/sigstore/cosign/issues/666)
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
* Added support for verifying with secrets from a Gitlab project (https://github.com/sigstore/cosign/pull/934)
* Added a `--k8s-keychain` option that enables cosign to support ambient registry credentials based on the "k8schain" library (https://github.com/sigstore/cosign/pull/972)
* CI (test) Images are now created for every architecture distroless ships on (currently: amd64, arm64, arm, s390x, ppc64le) (https://github.com/sigstore/cosign/pull/973)
* `attest`: replaced `--upload` flag with a `--no-upload` flag (https://github.com/sigstore/cosign/pull/979)

### Bug Fixes

* `cosigned` now verifies `CronJob` images (Terve, @vaikas https://github.com/sigstore/cosign/pull/809)
* Fixed the `verify` `--cert-email` option to actually work (Sweet as, @passcod https://github.com/sigstore/cosign/pull/821)
* `public-key -sk` no longer causes  `error: x509: unsupported public key type: *crypto.PublicKey` (https://github.com/sigstore/cosign/pull/864)
* Fixed interactive terminal support in Windows (https://github.com/sigstore/cosign/pull/871)
* The `-ct` flag is no longer ignored in `upload blob` (https://github.com/sigstore/cosign/pull/910)

### Contributors

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

## v1.2.0

### Enhancements
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

### Bug Fixes
* Fix verify-dockerfile to allow lowercase FROM (https://github.com/sigstore/cosign/pull/643)
* Fix signing for the cosigned image. (https://github.com/sigstore/cosign/pull/634)
* Make sure generate-key-pair doesn't overwrite existing key-pair (https://github.com/sigstore/cosign/pull/623)
* helm/ci: update helm repo before installing the dependency (https://github.com/sigstore/cosign/pull/598)
* Set the correct predicate type/URI for each supported predicate type. (https://github.com/sigstore/cosign/pull/592)
* Warnings on admissionregistration version (https://github.com/sigstore/cosign/pull/581)
* Remove unnecessary COSIGN_PASSWORD (https://github.com/sigstore/cosign/pull/572)

### Contributors
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


## v1.1.0

### Enhancements

* BREAKING: The `-attestation` flag has been renamed to `-predicate` in `attest` (https://github.com/sigstore/cosign/pull/500)
* Added `verify-manifest` command (https://github.com/sigstore/cosign/pull/490)
* Added the ability to specify and validate well-known attestation types in `attest` with the `-type` flag (https://github.com/sigstore/cosign/pull/504)
* Added `cosign init` command to setup the trusted local repository of SigStore's TUF root metadata (https://github.com/sigstore/cosign/pull/520)
* Added timestamps to Cosign's custom In-Toto predicate (https://github.com/sigstore/cosign/pull/533)
* `verify` now always verifies that the image exists (even when referenced by digest) before verification (https://github.com/sigstore/cosign/pull/543)

### Bug Fixes

* `verify-dockerfile` no longer fails on `FROM scratch` (https://github.com/sigstore/cosign/pull/509)
* Fixed reading from STDIN with `attach sbom` (https://github.com/sigstore/cosign/pull/517)
* Fixed broken documentation and implementation of `-output` for `verify` and `verify-attestation` (https://github.com/sigstore/cosign/pull/546)
* Fixed nil pointer error when calling `upload blob` without specifying `-f` (https://github.com/sigstore/cosign/pull/563)

### Contributors

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
