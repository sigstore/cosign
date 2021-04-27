# Changelog

## v0.4.0 (pending)

### Enhancements

* Support for Hashicorp vault as a KMS provider has been added

### Bug Fixes

### Contributors

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
