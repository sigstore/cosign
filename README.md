<p align="center">
  <img style="max-width: 100%;width: 300px;" src="./images/logo.svg" alt="Cosign logo"/>
</p>

# cosign

Container Signing, Verification and Storage in an OCI registry.

[![Go Report Card](https://goreportcard.com/badge/github.com/sigstore/cosign)](https://goreportcard.com/report/github.com/sigstore/cosign)
[![e2e-tests](https://github.com/sigstore/cosign/actions/workflows/e2e_tests.yml/badge.svg)](https://github.com/sigstore/cosign/actions/workflows/e2e_tests.yml)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/5715/badge)](https://bestpractices.coreinfrastructure.org/projects/5715)

Cosign aims to make signatures **invisible infrastructure**.

Cosign supports:

* Hardware and KMS signing
* Bring-your-own PKI
* Our free OIDC PKI ([Fulcio](https://github.com/sigstore/fulcio))
* Built-in binary transparency and timestamping service ([Rekor](https://github.com/sigstore/rekor))

![intro](images/intro.gif)

## Info

`Cosign` is developed as part of the [`sigstore`](https://sigstore.dev) project.
We also use a [slack channel](https://sigstore.slack.com)!
Click [here](https://join.slack.com/t/sigstore/shared_invite/zt-mhs55zh0-XmY3bcfWn4XEyMqUUutbUQ) for the invite link.

## Installation

For Homebrew, Arch, Nix, GitHub Action, and Kubernetes installs see the [installation docs](https://docs.sigstore.dev/cosign/installation).

For Linux and macOS binaries see the [GitHub release assets](https://github.com/sigstore/cosign/releases/latest).

## Developer Installation

If you have Go 1.17+, you can setup a development environment:

    $ git clone https://github.com/sigstore/cosign
    $ cd cosign
    $ go install ./cmd/cosign
    $ $(go env GOPATH)/bin/cosign

## Dockerfile
Here is how to install and use cosign inside a Dockerfile through the gcr.io/projectsigstore/cosign image:

```shell
FROM gcr.io/projectsigstore/cosign:v1.9.0 as cosign-bin

# Source: https://github.com/distroless/static
FROM ghcr.io/distroless/static:latest
COPY --from=cosign-bin /ko-app/cosign /usr/local/bin/cosign
ENTRYPOINT [ "cosign" ]
```

## Quick Start

This shows how to:

* generate a keypair
* sign a container image and store that signature in the registry
* find signatures for a container image, and verify them against a public key

See the [Usage documentation](USAGE.md) for more commands!

See the [FUN.md](FUN.md) documentation for some fun tips and tricks!

NOTE: you will need access to a container registry for cosign to work with.
[ttl.sh](https://ttl.sh) offers free, short-lived (ie: hours), anonymous container image
hosting if you just want to try these commands out.

### Generate a keypair

```shell
$ cosign generate-key-pair
Enter password for private key:
Enter again:
Private key written to cosign.key
Public key written to cosign.pub
```

### Sign a container and store the signature in the registry

```shell
$ cosign sign --key cosign.key dlorenc/demo
Enter password for private key:
Pushing signature to: index.docker.io/dlorenc/demo:sha256-87ef60f558bad79beea6425a3b28989f01dd417164150ab3baab98dcbf04def8.sig
```

The cosign command above prompts the user to enter the password for the private key.
The user can either manually enter the password, or if the environment variable `COSIGN_PASSWORD` is set then it is used automatically.


### Verify a container against a public key

This command returns `0` if *at least one* `cosign` formatted signature for the image is found
matching the public key.
See the detailed usage below for information and caveats on other signature formats.

Any valid payloads are printed to stdout, in json format.
Note that these signed payloads include the digest of the container image, which is how we can be
sure these "detached" signatures cover the correct image.

```shell
$ cosign verify --key cosign.pub dlorenc/demo
The following checks were performed on these signatures:
  - The cosign claims were validated
  - The signatures were verified against the specified public key
{"Critical":{"Identity":{"docker-reference":""},"Image":{"Docker-manifest-digest":"sha256:87ef60f558bad79beea6425a3b28989f01dd417164150ab3baab98dcbf04def8"},"Type":"cosign container image signature"},"Optional":null}
```

## `Cosign` is 1.0!

This means the core feature set of `cosign` is considered ready for production use.
This core set includes:

### Key Management

* fixed, text-based keys generated using `cosign generate-key-pair`
* cloud KMS-based keys generated using `cosign generate-key-pair -kms`
* keys generated on hardware tokens using the PIV interface using `cosign piv-tool`
* Kubernetes-secret based keys generated using `cosign generate-key-pair k8s://namespace/secretName`

### Artifact Types

* OCI and Docker Images
* Other artifacts that can be stored in a container registry, including:
  * Tekton Bundles
  * Helm Charts
  * WASM modules
  * eBPF modules
  * (probably anything else, feel free to add things to this list)
* Text files and other binary blobs, using `cosign sign-blob`

### What ** is not ** production ready?

While parts of `cosign` are stable, we are continuing to experiment and add new features.
The following feature set is not considered stable yet, but we are committed to stabilizing it over time!

#### Anything under the `COSIGN_EXPERIMENTAL` environment variable

* Integration with the `Rekor` transparency log
* Keyless signatures using the `Fulcio` CA

#### Formats/Specifications

While the `cosign` code for uploading, signing, retrieving, and verifying several artifact types is stable,
the format specifications for some of those types may not be considered stable yet.
Some of these are developed outside of the `cosign` project, so we are waiting for them to stabilize first.

These include:

* The SBOM specification for storing SBOMs in a container registry
* The In-Toto attestation format

## Working with Other Artifacts

OCI registries are useful for storing more than just container images!
`Cosign` also includes some utilities for publishing generic artifacts, including binaries, scripts, and configuration files using the OCI protocol.

This section shows how to leverage these for an easy-to-use, backwards-compatible artifact distribution system that integrates well with the rest of Sigstore.

### Blobs

You can publish an artifact with `cosign upload blob`:

```shell
$ echo "my first artifact" > artifact
$ cosign upload blob -f artifact gcr.io/dlorenc-vmtest2/artifact
Uploading file from [artifact] to [gcr.io/dlorenc-vmtest2/artifact:latest] with media type [text/plain; charset=utf-8]
File is available directly at [us.gcr.io/v2/dlorenc-vmtest2/readme/blobs/sha256:b57400c0ad852a7c2f6f7da4a1f94547692c61f3e921a49ba3a41805ae8e1e99]
us.gcr.io/dlorenc-vmtest2/readme@sha256:4aa3054270f7a70b4528f2064ee90961788e1e1518703592ae4463de3b889dec
```

Your users can download it from the "direct" url with standard tools like curl or wget:

```shell
$ curl -L gcr.io/v2/dlorenc-vmtest2/artifact/blobs/sha256:97f16c28f6478f3c02d7fff4c7f3c2a30041b72eb6852ca85b919fd85534ed4b > artifact
```

The digest is baked right into the URL, so they can check that as well:

```shell
$ curl -L gcr.io/v2/dlorenc-vmtest2/artifact/blobs/sha256:97f16c28f6478f3c02d7fff4c7f3c2a30041b72eb6852ca85b919fd85534ed4b | shasum -a 256
97f16c28f6478f3c02d7fff4c7f3c2a30041b72eb6852ca85b919fd85534ed4b  -
```

You can sign it with the normal `cosign sign` command and flags:

```shell
$ cosign sign --key cosign.key gcr.io/dlorenc-vmtest2/artifact
Enter password for private key:
Pushing signature to: gcr.io/dlorenc-vmtest2/artifact:sha256-3f612a4520b2c245d620d0cca029f1173f6bea76819dde8543f5b799ea3c696c.sig
```
#### sget

We also include the `sget` command for safer, automatic verification of signatures and integration with our binary transparency log, Rekor.

To install `sget`, if you have Go 1.16+, you can directly run:

    $ go install github.com/sigstore/cosign/cmd/sget@latest

and the resulting binary will be placed at `$GOPATH/bin/sget` (or `$GOBIN/sget`, if set).

Just like `curl`, `sget` can be used to fetch artifacts by digest using the OCI URL.
Digest verification is automatic:

```shell
$ sget us.gcr.io/dlorenc-vmtest2/readme@sha256:4aa3054270f7a70b4528f2064ee90961788e1e1518703592ae4463de3b889dec > artifact
```

You can also use `sget` to fetch contents by tag.
Fetching contents without verifying them is dangerous, so we require the artifact be signed in this case:

```shell
$ sget gcr.io/dlorenc-vmtest2/artifact
error: public key must be specified when fetching by tag, you must fetch by digest or supply a public key

$ sget --key cosign.pub us.gcr.io/dlorenc-vmtest2/readme > foo

Verification for us.gcr.io/dlorenc-vmtest2/readme --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key
  - Any certificates were verified against the Fulcio roots.
```

The signature, claims and transparency log proofs are all verified automatically by sget as part of the download.

`curl | bash` isn't a great idea, but `sget | bash` is less-bad.

#### Tekton Bundles

[Tekton](https://tekton.dev) bundles can be uploaded and managed within an OCI registry.
The specification is [here](https://tekton.dev/docs/pipelines/tekton-bundle-contracts/).
This means they can also be signed and verified with `cosign`.

Tekton Bundles can currently be uploaded with the [tkn cli](https://github.com/tektoncd/cli), but we may add this support to
`cosign` in the future.

```shell
$ tkn bundle push us.gcr.io/dlorenc-vmtest2/pipeline:latest -f task-output-image.yaml
Creating Tekton Bundle:
        - Added TaskRun:  to image

Pushed Tekton Bundle to us.gcr.io/dlorenc-vmtest2/pipeline@sha256:124e1fdee94fe5c5f902bc94da2d6e2fea243934c74e76c2368acdc8d3ac7155
$ cosign sign --key cosign.key us.gcr.io/dlorenc-vmtest2/pipeline:latest
Enter password for private key:
tlog entry created with index: 5086
Pushing signature to: us.gcr.io/dlorenc-vmtest2/demo:sha256-124e1fdee94fe5c5f902bc94da2d6e2fea243934c74e76c2368acdc8d3ac7155.sig
```

#### WASM

Web Assembly Modules can also be stored in an OCI registry, using this [specification](https://github.com/solo-io/wasm/tree/master/spec).

Cosign can upload these using the `cosign wasm upload` command:

```shell
$ cosign upload wasm -f hello.wasm us.gcr.io/dlorenc-vmtest2/wasm
$ cosign sign --key cosign.key us.gcr.io/dlorenc-vmtest2/wasm
Enter password for private key:
tlog entry created with index: 5198
Pushing signature to: us.gcr.io/dlorenc-vmtest2/wasm:sha256-9e7a511fb3130ee4641baf1adc0400bed674d4afc3f1b81bb581c3c8f613f812.sig
```
#### eBPF

[eBPF](https://ebpf.io) modules can also be stored in an OCI registry, using this [specification](https://github.com/solo-io/bumblebee/tree/main/spec).

The image below was built using the `bee` tool. More information can be found [here](https://github.com/solo-io/bumblebee/)

Cosign can then sign these images as they can any other OCI image.

```shell
$ bee build ./examples/tcpconnect/tcpconnect.c localhost:5000/tcpconnect:test
$ bee push localhost:5000/tcpconnect:test
$ cosign sign  --key cosign.key localhost:5000/tcpconnect:test
Enter password for private key:
Pushing signature to: localhost:5000/tcpconnect
$ cosign verify --key cosign.pub localhost:5000/tcpconnect:test
cosign verify --key pubkey.pem localhost:5001/tcpconnect:test

Verification for localhost:5000/tcpconnect:test --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - The signatures were verified against the specified public key

[{"critical":{"identity":{"docker-reference":"localhost:5000/tcpconnect"},"image":{"docker-manifest-digest":"sha256:7a91c50d922925f152fec96ed1d84b7bc6b2079c169d68826f6cf307f22d40e6"},"type":"cosign container image signature"},"optional":null}]

```

#### In-Toto Attestations

Cosign also has built-in support for [in-toto](https://in-toto.io) attestations.
The specification for these is defined [here](https://github.com/in-toto/attestation).

You can create and sign one from a local predicate file using the following commands:

```shell
$ cosign attest --predicate <file> --key cosign.key <image>
```

All of the standard key management systems are supported.
Payloads are signed using the DSSE signing spec, defined [here](https://github.com/secure-systems-lab/dsse).

To verify:

```shell
$ cosign verify-attestation --key cosign.pub <image>
```

## Detailed Usage

See the [Usage documentation](USAGE.md) for more commands!

## Hardware-based Tokens

See the [Hardware Tokens documentation](TOKENS.md) for information on how to use `cosign` with hardware.

## Keyless

🚨 🚨 🚨 See [here](KEYLESS.md) for info on the experimental Keyless signatures mode. 🚨 🚨 🚨

## Registry Support

`cosign` uses [go-containerregistry](https://github.com/google/go-containerregistry) for registry
interactions, which has generally excellent compatibility, but some registries may have quirks.

Today, `cosign` has been tested and works against the following registries:

* AWS Elastic Container Registry
* GCP's Artifact Registry and Container Registry
* Docker Hub
* Azure Container Registry
* JFrog Artifactory Container Registry
* The CNCF distribution/distribution Registry
* GitLab Container Registry
* GitHub Container Registry
* The CNCF Harbor Registry
* Digital Ocean Container Registry
* Sonatype Nexus Container Registry
* Alibaba Cloud Container Registry
* Red Hat Quay Container Registry 3.6+ / Red Hat quay.io
* Elastic Container Registry
* IBM Cloud Container Registry
* Cloudsmith Container Registry

We aim for wide registry support. To `sign` images in registries which do not yet fully support [OCI media types](https://github.com/sigstore/cosign/blob/main/SPEC.md#object-types), one may need to use `COSIGN_DOCKER_MEDIA_TYPES` to fall back to legacy equivalents. For example:
```shell
COSIGN_DOCKER_MEDIA_TYPES=1 cosign sign --key cosign.key legacy-registry.example.com/my/image
```

Please help test and file bugs if you see issues!
Instructions can be found in the [tracking issue](https://github.com/sigstore/cosign/issues/40).

## Rekor Support
_Note: this is an experimental feature_

To publish signed artifacts to a Rekor transparency log and verify their existence in the log
set the `COSIGN_EXPERIMENTAL=1` environment variable.

```shell
$ COSIGN_EXPERIMENTAL=1 cosign sign --key cosign.key dlorenc/demo
$ COSIGN_EXPERIMENTAL=1 cosign verify --key cosign.pub dlorenc/demo
```

`cosign` defaults to using the public instance of rekor at [rekor.sigstore.dev](https://rekor.sigstore.dev).
To configure the rekor server, use the -`rekor-url` flag

## Caveats

### Intentionally Missing Features

`cosign` only generates ECDSA-P256 keys and uses SHA256 hashes.
Keys are stored in PEM-encoded PKCS8 format.
However, you can use `cosign` to store and retrieve signatures in any format, from any algorithm.

### Unintentionally Missing Features

`cosign` will integrate with transparency logs!
See https://github.com/sigstore/cosign/issues/34 for more info.

`cosign` will integrate with even more transparency logs, and a PKI.
See https://github.com/sigStore/fulcio for more info.

`cosign` will also support The Update Framework for delegations, key discovery and expiration.
See https://github.com/sigstore/cosign/issues/86 for more info!

### Things That Should Probably Change

#### Payload Formats

`cosign` only supports Red Hat's [simple signing](https://www.redhat.com/en/blog/container-image-signing)
format for payloads.
That looks like:

```json
{
    "critical": {
           "identity": {
               "docker-reference": "testing/manifest"
           },
           "image": {
               "Docker-manifest-digest": "sha256:20be...fe55"
           },
           "type": "cosign container image signature"
    },
    "optional": {
           "creator": "Bob the Builder",
           "timestamp": 1458239713
    }
}
```
**Note:** This can be generated for an image reference using `cosign generate <image>`.

I'm happy to switch this format to something else if it makes sense.
See https://github.com/notaryproject/nv2/issues/40 for one option.


#### Registry Details

`cosign` signatures are stored as separate objects in the OCI registry, with only a weak
reference back to the object they "sign".
This means this relationship is opaque to the registry, and signatures *will not* be deleted
or garbage-collected when the image is deleted.
Similarly, they **can** easily be copied from one environment to another, but this is not
automatic.

Multiple signatures are stored in a list which is unfortunately a race condition today.
To add a signature, clients orchestrate a "read-append-write" operation, so the last write
will win in the case of contention.

##### Specifying Registry
`cosign` will default to storing signatures in the same repo as the image it is signing.
To specify a different repo for signatures, you can set the `COSIGN_REPOSITORY` environment variable.

This will replace the repo in the provided image like this:
```
$ export COSIGN_REPOSITORY=gcr.io/my-new-repo
$ gcr.io/dlorenc-vmtest2/demo -> gcr.io/my-new-repo/demo:sha256-DIGEST.sig
```
So the signature for `gcr.io/dlorenc-vmtest2/demo` will be stored in `gcr.io/my-new-repo/demo:sha256-DIGEST.sig`.


## Signature Specification

`cosign` is inspired by tools like [minisign](https://jedisct1.github.io/minisign/) and
[signify](https://www.openbsd.org/papers/bsdcan-signify.html).

Generated private keys are stored in PEM format.
The keys encrypted under a password using scrypt as a KDF and nacl/secretbox for encryption.

They have a PEM header of `ENCRYPTED COSIGN PRIVATE KEY`:

```
-----BEGIN ENCRYPTED COSIGN PRIVATE KEY-----
...
-----END ENCRYPTED COSIGN PRIVATE KEY-----
```

Public keys are stored on disk in PEM-encoded standard PKIX format with a header of `PUBLIC KEY`.
```
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELigCnlLNKgOglRTx1D7JhI7eRw99
QolE9Jo4QUxnbMy5nUuBL+UZF9qqfm/Dg1BNeHRThHzWh2ki9vAEgWEDOw==
-----END PUBLIC KEY-----
```

## Storage Specification

`cosign` stores signatures in an OCI registry, and uses a naming convention (tag based
on the sha256 of what we're signing) for locating the signature index.

<p align="center">
  <img src="/images/signatures.dot.svg" />
</p>

`reg.example.com/ubuntu@sha256:703218c0465075f4425e58fac086e09e1de5c340b12976ab9eb8ad26615c3715` has signatures located at `reg.example.com/ubuntu:sha256-703218c0465075f4425e58fac086e09e1de5c340b12976ab9eb8ad26615c3715.sig`

Roughly (ignoring ports in the hostname): `s/:/-/g` and `s/@/:/g` to find the signature index.

See [Race conditions](#registry-details) for some caveats around this strategy.

Alternative implementations could use transparency logs, local filesystem, a separate repository
registry, an explicit reference to a signature index, a new registry API, grafeas, etc.

### Signing subjects

`cosign` only works for artifacts stored as "manifests" in the registry today.
The proposed mechanism is flexible enough to support signing arbitrary things.

### KMS Support

`cosign` supports using a KMS provider to generate and sign keys.
Right now cosign supports Hashicorp Vault, AWS KMS, GCP KMS, Azure Key Vault and we are hoping to support more in the future!

See the [KMS docs](KMS.md) for more details.

### OCI Artifacts

Push an artifact to a registry using [oras](https://github.com/deislabs/oras) (in this case, `cosign` itself!):

```shell
$ oras push us-central1-docker.pkg.dev/dlorenc-vmtest2/test/artifact ./cosign
Uploading f53604826795 cosign
Pushed us-central1-docker.pkg.dev/dlorenc-vmtest2/test/artifact
Digest: sha256:551e6cce7ed2e5c914998f931b277bc879e675b74843e6f29bc17f3b5f692bef
```

Now sign it! Using `cosign` of course:

```shell
$ cosign sign --key cosign.key us-central1-docker.pkg.dev/dlorenc-vmtest2/test/artifact@sha256:551e6cce7ed2e5c914998f931b277bc879e675b74843e6f29bc17f3b5f692bef
Enter password for private key:
Pushing signature to: us-central1-docker.pkg.dev/dlorenc-vmtest2/test/artifact:sha256-551e6cce7ed2e5c914998f931b277bc879e675b74843e6f29bc17f3b5f692bef.sig
```

Finally, verify `cosign` with `cosign` again:

```shell
$ cosign verify --key cosign.pub  us-central1-docker.pkg.dev/dlorenc-vmtest2/test/artifact@sha256:551e6cce7ed2e5c914998f931b277bc879e675b74843e6f29bc17f3b5f692bef
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - The claims were present in the transparency log
  - The signatures were integrated into the transparency log when the certificate was valid
  - The signatures were verified against the specified public key
  - Any certificates were verified against the Fulcio roots.

{"Critical":{"Identity":{"docker-reference":""},"Image":{"Docker-manifest-digest":"sha256:551e6cce7ed2e5c914998f931b277bc879e675b74843e6f29bc17f3b5f692bef"},"Type":"cosign container image signature"},"Optional":null}
```

## FAQ

### Why not use Notary v2

It's hard to answer this briefly.
This post contains some comparisons:

[Notary V2 and Cosign](https://medium.com/@dlorenc/notary-v2-and-cosign-b816658f044d)

If you find other comparison posts, please send a PR here and we'll link them all.

### Why not use containers/image signing

`containers/image` signing is close to `cosign`, and we reuse payload formats.
`cosign` differs in that it signs with ECDSA-P256 keys instead of PGP, and stores
signatures in the registry.

### Why not use TUF?

I believe this tool is complementary to TUF, and they can be used together.
I haven't tried yet, but think we can also reuse a registry for TUF storage.

### Why not use Blockchain?

Just kidding. Nobody actually asked this. Don't be that person.

### Why not use $FOO?

See the next section, [Requirements](#Requirements).
I designed this tool to meet a few specific requirements, and didn't find
anything else that met all of these.
If you're aware of another system that does meet these, please let me know!

## Design Requirements

* No external services for signature storage, querying, or retrieval
* We aim for as much registry support as possible
* Everything should work over the registry API
* PGP should not be required at all.
* Users must be able to find all signatures for an image
* Signers can sign an image after push
* Multiple entities can sign an image
* Signing an image does not mutate the image
* Pure-go implementation

## Future Ideas

### Registry API Changes

The naming convention and read-modify-write update patterns we use to store things in
a registry are a bit, well, "hacky".
I think they're the best (only) real option available today, but if the registry API
changes we can improve these.

### Other Types

`cosign` can sign anything in a registry.
These examples show signing a single image, but you could also sign a multi-platform `Index`,
or any other type of artifact.
This includes Helm Charts, Tekton Pipelines, and anything else currently using OCI registries
for distribution.

This also means new artifact types can be uploaded to a registry and signed.
One interesting type to store and sign would be TUF repositories.
I haven't tried yet, but I'm fairly certain TUF could be implemented on top of this.

### Tag Signing

`cosign` signatures protect the digests of objects stored in a registry.
The optional `annotations` support (via the `-a` flag to `cosign sign`) can be used to add extra
data to the payload that is signed and protected by the signature.
One use-case for this might be to sign a tag->digest mapping.

If you would like to attest that a specific tag (or set of tags) should point at a digest, you can
run something like:

```shell
$ TAG=sign-me
$ DGST=$(crane digest dlorenc/demo:$TAG)
$ cosign sign --key cosign.key -a tag=$TAG dlorenc/demo@$DGST
Enter password for private key:
Pushing signature to: dlorenc/demo:sha256-97fc222cee7991b5b061d4d4afdb5f3428fcb0c9054e1690313786befa1e4e36.sig
```

Then you can verify that the tag->digest mapping is also covered in the signature, using the `-a` flag to `cosign verify`.
This example verifies that the digest `$TAG` points to (`sha256:97fc222cee7991b5b061d4d4afdb5f3428fcb0c9054e1690313786befa1e4e36`)
has been signed, **and also** that the `$TAG`:

```shell
$ cosign verify --key cosign.pub -a tag=$TAG dlorenc/demo:$TAG | jq .
{
  "Critical": {
    "Identity": {
      "docker-reference": ""
    },
    "Image": {
      "Docker-manifest-digest": "97fc222cee7991b5b061d4d4afdb5f3428fcb0c9054e1690313786befa1e4e36"
    },
    "Type": "cosign container image signature"
  },
  "Optional": {
    "tag": "sign-me"
  }
}
```

Timestamps could also be added here, to implement TUF-style freeze-attack prevention.

### Base Image/Layer Signing

Again, `cosign` can sign anything in a registry.
You could use `cosign` to sign an image that is intended to be used as a base image,
and include that provenance metadata in resulting derived images.
This could be used to enforce that an image was built from an authorized base image.

Rough Idea:
* OCI manifests have an ordered list of `layer` `Descriptors`, which can contain annotations.
  See [here](https://github.com/opencontainers/image-spec/blob/master/manifest.md) for the
  specification.
* A base image is an ordered list of layers to which other layers are appended, as well as an
  initial configuration object that is mutated.
  * A derived image is free to completely delete/destroy/recreate the config from its base image,
    so signing the config would provided limited value.
* We can sign the full set of ordered base layers, and attach that signature as an annotation to
  the **last** layer in the resulting child image.

This example manifest manifest represents an image that has been built from a base image with two
layers.
One additional layer is added, forming the final image.

```json
{
  "schemaVersion": 2,
  "config": {
    "mediaType": "application/vnd.oci.image.config.v1+json",
    "size": 7023,
    "digest": "sha256:b5b2b2c507a0944348e0303114d8d93aaaa081732b86451d9bce1f432a537bc7"
  },
  "layers": [
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "size": 32654,
      "digest": "sha256:9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0"
    },
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "size": 16724,
      "digest": "sha256:3c3a4604a545cdc127456d94e421cd355bca5b528f4a9c1905b15da2eb4a4c6b",
      "annotations": {
        "dev.cosign.signature.baseimage": "Ejy6ipGJjUzMDoQFePWixqPBYF0iSnIvpMWps3mlcYNSEcRRZelL7GzimKXaMjxfhy5bshNGvDT5QoUJ0tqUAg=="
      }
    },
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "size": 73109,
      "digest": "sha256:ec4b8955958665577945c89419d1af06b5f7636b4ac3da7f12184802ad867736"
    }
  ],
}
```

Note that this could be applied recursively, for multiple intermediate base images.

### Counter-Signing

Cosign signatures (and their protected payloads) are stored as artifacts in a registry.
These signature objects can also be signed, resulting in a new, "counter-signature" artifact.
This "counter-signature" protects the signature (or set of signatures) **and** the referenced artifact, which allows
it to act as an attestation to the **signature(s) themselves**.

Before we sign the signature artifact, we first give it a memorable name so we can find it later.

```shell
$ cosign sign --key cosign.key -a sig=original dlorenc/demo
Enter password for private key:
Pushing signature to: dlorenc/demo:sha256-97fc222cee7991b5b061d4d4afdb5f3428fcb0c9054e1690313786befa1e4e36.sig
$ cosign verify --key cosign.pub dlorenc/demo | jq .
{
  "Critical": {
    "Identity": {
      "docker-reference": ""
    },
    "Image": {
      "Docker-manifest-digest": "97fc222cee7991b5b061d4d4afdb5f3428fcb0c9054e1690313786befa1e4e36"
    },
    "Type": "cosign container image signature"
  },
  "Optional": {
    "sig": "original"
  }
}
```

Now give that signature a memorable name, then sign that:

```shell
$ crane tag $(cosign triangulate dlorenc/demo) mysignature
2021/02/15 20:22:55 dlorenc/demo:mysignature: digest: sha256:71f70e5d29bde87f988740665257c35b1c6f52dafa20fab4ba16b3b1f4c6ba0e size: 556
$ cosign sign --key cosign.key -a sig=counter dlorenc/demo:mysignature
Enter password for private key:
Pushing signature to: dlorenc/demo:sha256-71f70e5d29bde87f988740665257c35b1c6f52dafa20fab4ba16b3b1f4c6ba0e.sig
$ cosign verify --key cosign.pub dlorenc/demo:mysignature
{"Critical":{"Identity":{"docker-reference":""},"Image":{"Docker-manifest-digest":"71f70e5d29bde87f988740665257c35b1c6f52dafa20fab4ba16b3b1f4c6ba0e"},"Type":"cosign container image signature"},"Optional":{"sig":"counter"}}
```

Finally, check the original signature:

```shell
$ crane manifest dlorenc/demo@sha256:71f70e5d29bde87f988740665257c35b1c6f52dafa20fab4ba16b3b1f4c6ba0e
{
  "schemaVersion": 2,
  "config": {
    "mediaType": "application/vnd.oci.image.config.v1+json",
    "size": 233,
    "digest": "sha256:3b25a088710d03f39be26629d22eb68cd277a01673b9cb461c4c24fbf8c81c89"
  },
  "layers": [
    {
      "mediaType": "application/vnd.oci.descriptor.v1+json",
      "size": 217,
      "digest": "sha256:0e79a356609f038089088ec46fd95f4649d04de989487220b1a0adbcc63fadae",
      "annotations": {
        "dev.sigstore.cosign/signature": "5uNZKEP9rm8zxAL0VVX7McMmyArzLqtxMTNPjPO2ns+5GJpBeXg+i9ILU+WjmGAKBCqiexTxzLC1/nkOzD4cDA=="
      }
    }
  ]
}
```

## Security

Should you discover any security issues, please refer to sigstore's [security
process](https://github.com/sigstore/.github/blob/main/SECURITY.md)
