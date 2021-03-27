# cosign

Container Signing, Verification and Storage in an OCI registry.

Cosign aims to make signatures **invisible infrastructure**.

![intro](images/intro.gif)

## Info

`Cosign` is developed as part of the [`sigstore`](https://sigstore.dev) project.
We also use a slack [slack channel](https://sigstore.slack.com)!
Click [here](https://join.slack.com/t/sigstore/shared_invite/zt-mhs55zh0-XmY3bcfWn4XEyMqUUutbUQ) for the invite link.

🚨 🚨 🚨 See [here](KEYLESS.md) for info on the experimental Keyless signatures mode. 🚨 🚨 🚨 

## Installation

If you have Go 1.16+, you can directly install by running:

    $ go install github.com/sigstore/cosign/cmd/cosign@latest

and the resulting binary will be placed at `$HOME/go/bin/cosign`.

### Containers

CI Built containers are published for every commit at `gcr.io/projectsigstore/cosign/ci/cosign`.
They are tagged with the commit.
They can be found with `crane ls`:

```
$ crane ls gcr.io/projectsigstore/cosign/ci/cosign
749f896
749f896bb378aca5cb45c5154fc0cb43f6728d48
```

### Releases

Releases are published in this repository under the Releases page, and hosted in the GCS bucket `cosign-releases`.
They can be viewed with `gsutil`:

```
$ gsutil ls gs://cosign-releases/v0.1.0
gs://cosign-releases/v0.1.0/cosign
gs://cosign-releases/v0.1.0/cosign.sha256
gs://cosign-releases/v0.1.0/cosign.sig
```

Cross platform builds will start in v0.2.0.

## Quick Start

This shows how to:

* generate a keypair
* sign a container image and store that signature in the registry
* find signatures for a container image, and verify them against a public key

See the [Usage documentation](USAGE.md) for more commands!

See the [FUN.md](FUN.md) documentation for some fun tips and tricks!

### Generate a keypair

```
$ cosign generate-key-pair
Enter password for private key:
Enter again:
Private key written to cosign.key
Public key written to cosign.key
```

### Sign a container and store the signature in the registry

```
$ cosign sign -key cosign.key dlorenc/demo
Enter password for private key:
Pushing signature to: index.docker.io/dlorenc/demo:sha256-87ef60f558bad79beea6425a3b28989f01dd417164150ab3baab98dcbf04def8.cosign
```

### Verify a container against a public key

This command returns 0 if *at least one* `cosign` formatted signature for the image is found
matching the public key.
See the detailed usage below for information and caveats on other signature formats.

Any valid payloads are printed to stdout, in json format.
Note that these signed payloads include the digest of the container image, which is how we can be
sure these "detached" signatures cover the correct image.

```
$ cosign verify -key cosign.pub dlorenc/demo
The following checks were performed on these signatures:
  - The cosign claims were validated
  - The signatures were verified against the specified public key
{"Critical":{"Identity":{"docker-reference":""},"Image":{"Docker-manifest-digest":"sha256:87ef60f558bad79beea6425a3b28989f01dd417164150ab3baab98dcbf04def8"},"Type":"cosign container signature"},"Optional":null}
```

## Detailed Usage

See the [Usage documentation](USAGE.md) for more commands!

## Rekor Support
_Note: this is an experimental feature_

To publish signed artifacts to a Rekor transparency log and verify their existence in the log
set the `COSIGN_EXPERIMENTAL=1` environment variable.

```
COSIGN_EXPERIMENTAL=1 cosign sign -key cosign.key dlorenc/demo
COSIGN_EXPERIMENTAL=1 cosign verify -key cosign.pub dlorenc/demo
```

`cosign` defaults to using the public instance of rekor at [api.rekor.dev](https://api.rekor.dev).
To configure the rekor server, set the `REKOR_SERVER` env variable.

## Caveats

### Intentionally Missing Features

`cosign` only generates ECDSA-P256 keys and uses SHA256 hashes.
Keys are stored in PEM-encoded PKCS8 format.
However, you can use `cosign` to store and retrieve signatures in any format, from any algorithm.

`cosign` does not handle key-distribution or PKI.

`cosign` does not handle expiry or revocation.
See [here](https://github.com/notaryproject/requirements/pull/47) for some discussion on the topic.

`cosign` does not handle public-key management or storage.
There are no keyrings or local state.

### Unintentionally Missing Features

`cosign` will integrate with transparency logs!
See https://github.com/sigstore/cosign/issues/34 for more info.

`cosign` will integrate with even more transparency logs, and a PKI.
See https://github.com/sigStore/fulcio for more info.

### Registry Support

`cosign` uses [go-containerregistry](github.com/google/go-containerregistry) for registry
interactions, which has excellent support, but other registries may have quirks.

Today, `cosign` has been tested and works against the following registries:

* GCP's Artifact Registry and Container Registry
* Docker Hub
* Azure Container Registry
* JFrog Artifactory Container Registry
* The CNCF distribution/distribution Registry
* Gitlab Container Registry
* GitHub Container Registry

We aim for wide registry support.
Please help test!
See https://github.com/sigstore/cosign/issues/40 for the tracking issue.

### Things That Should Probably Change

#### Payload Formats

`cosign` only supports Red Hat's [simple signing](https://www.redhat.com/en/blog/container-image-signing)
format for payloads.
That looks like:

```
{
    "critical": {
           "identity": {
               "docker-reference": "testing/manifest"
           },
           "image": {
               "Docker-manifest-digest": "sha256:20be...fe55"
           },
           "type": "cosign container signature"
    },
    "optional": {
           "creator": "atomic",
           "timestamp": 1458239713
    }
}
```
**Note:** This can be generated for an image reference using `cosign generate <image>`.

I'm happy to switch this format to something else if it makes sense.
See [https://github.com/notaryproject/nv2/issues/40] for one option.


#### Registry Details

`cosign` signatures are stored as separate objects in the OCI registry, with only a weak
reference back to the object they "sign".
This means this relationship is opaque to the registry, and signatures *will not* be deleted
or garbage-collected when the image is deleted.
Similarly, they **can** easily be copied from one environment to another, but this is not
automatic.

Multiple signatures are stored in a list which is unfortunately "racy" today.
To add a signtaure, clients orchestrate a "read-append-write" operation, so the last write
will win in the case of contention.

##### Specifying Registry
`cosign` will default to storing signatures in the same repo as the image it is signing.
To specify a different repo for signatures, you can set the `COSIGN_REPOSITORY` environment variable.

This will replace the repo in the provided image like this:
```
export COSIGN_REPOSITORY=gcr.io/my-new-repo
gcr.io/dlorenc-vmtest2/demo -> gcr.io/my-new-repo/demo:sha256-DIGEST.cosign
```
So the signature for `gcr.io/dlorenc-vmtest2/demo` will be stored in `gcr.io/my-new-repo/demo:sha256-DIGEST.cosign`.


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
NqfC4CpZiE4OGpuYFSSMzXHJqXQ6u1W55prrZIjjZJ0=
-----END PUBLIC KEY-----
```

The inner (base64 encoded) data portion can be supplied directly on the command line without the PEM blocks:

```
$ cosign verify -key NqfC4CpZiE4OGpuYFSSMzXHJqXQ6u1W55prrZIjjZJ0= us-central1-docker.pkg.dev/dlorenc-vmtest2/test/taskrun
```

## Storage Specification

`cosign` stores signatures in an OCI registry, and uses a naming convention (tag based
on the sha256 of what we're signing) for locating the signature index.

<p align="center">
  <img src="/images/signatures.dot.svg" />
</p>

`reg.example.com/ubuntu@sha256:703218c0465075f4425e58fac086e09e1de5c340b12976ab9eb8ad26615c3715` has signatures located at `reg.example.com/ubuntu:sha256-703218c0465075f4425e58fac086e09e1de5c340b12976ab9eb8ad26615c3715`

Roughly (ignoring ports in the hostname): `s/:/-/g` and `s/@/:/g` to find the signature index.

See [Race conditions](#race-conditions) for some caveats around this strategy.

Alternative implementations could use transparency logs, local filesystem, a separate repository
registry, an explicit reference to a signature index, a new registry API, grafeas, etc.

### Signing subjects

`cosign` only works for artifacts stored as "manifests" in the registry today.
The proposed mechanism is flexible enough to support signing arbitrary things.

### KMS Support
`cosign` supports using a KMS provider to generate and sign keys.
Right now we only support GCP KMS, but are hoping to support more in the future! 

To generate a key in GCP KMS (and a key ring, if necessary) run:
```
cosign generate-key-pair -kms gcpkms://projects/<PROJECT ID>/locations/<LOCATION>/keyRings/<KEY_RING>/cryptoKeys/<KEY_NAME>
```
This command will also save the public key to a file locally, which can be used for verification later on.

To sign an image run:
```
cosign sign -kms gcpkms://projects/<PROJECT ID>/locations/<LOCATION>/keyRings/<KEY_RING>/cryptoKeys/<KEY_NAME> dlorenc/demo
```

and to verify with the public key in KMS:
```
cosign verify -kms gcpkms://projects/<PROJECT ID>/locations/<LOCATION>/keyRings/<KEY_RING>/cryptoKeys/<KEY_NAME> dlorenc/demo
```

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
$ cosign sign -key cosign.key us-central1-docker.pkg.dev/dlorenc-vmtest2/test/artifact@sha256:551e6cce7ed2e5c914998f931b277bc879e675b74843e6f29bc17f3b5f692bef
Enter password for private key:
Pushing signature to: us-central1-docker.pkg.dev/dlorenc-vmtest2/test/artifact:sha256-551e6cce7ed2e5c914998f931b277bc879e675b74843e6f29bc17f3b5f692bef.cosign
```

Finally, verify `cosign` with `cosign` again:

```shell
$ cosign verify -key cosign.pub  us-central1-docker.pkg.dev/dlorenc-vmtest2/test/artifact@sha256:551e6cce7ed2e5c914998f931b277bc879e675b74843e6f29bc17f3b5f692bef
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - The claims were present in the transparency log
  - The signatures were integrated into the transparency log when the certificate was valid
  - The signatures were verified against the specified public key
  - Any certificates were verified against the Fulcio roots.
{"Critical":{"Identity":{"docker-reference":""},"Image":{"Docker-manifest-digest":"sha256:551e6cce7ed2e5c914998f931b277bc879e675b74843e6f29bc17f3b5f692bef"},"Type":"cosign container signature"},"Optional":null}
```

## FAQ

### Who is using this?

Hopefully no one yet. Stay tuned, though.

### Why not use Notary v2

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
a registry a bit, well, "hacky".
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
$ cosign sign -key cosign.key -a tag=$TAG dlorenc/demo@$DGST
Enter password for private key:
Pushing signature to: dlorenc/demo:sha256-97fc222cee7991b5b061d4d4afdb5f3428fcb0c9054e1690313786befa1e4e36.cosign
```

Then you can verify that the tag->digest mapping is also covered in the signature, using the `-a` flag to `cosign verify`.
This example verifes that the digest `$TAG` points to (`sha256:97fc222cee7991b5b061d4d4afdb5f3428fcb0c9054e1690313786befa1e4e36`)
has been signed, **and also** that the `$TAG`:

```
$ cosign verify -key cosign.pub -a tag=$TAG dlorenc/demo:$TAG | jq .
{
  "Critical": {
    "Identity": {
      "docker-reference": ""
    },
    "Image": {
      "Docker-manifest-digest": "97fc222cee7991b5b061d4d4afdb5f3428fcb0c9054e1690313786befa1e4e36"
    },
    "Type": "cosign container signature"
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
and inlcude that provenance metadata in resulting derived images.
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

Cosign signatures (and their protected paylaods) are stored as artifacts in a registry.
These signature objects can also be signed, resulting in a new, "counter-signature" artifact.
This "counter-signature" protects the signature (or set of signatures) **and** the referenced artifact, which allows
it to act as an attestation to the **signature(s) themselves**.

Before we sign the signature artifact, we first give it a memorable name so we can find it later.

```shell
$ cosign sign -key cosign.key -a sig=original dlorenc/demo
Enter password for private key:
Pushing signature to: dlorenc/demo:sha256-97fc222cee7991b5b061d4d4afdb5f3428fcb0c9054e1690313786befa1e4e36.cosign
$ cosign verify -key cosign.pub dlorenc/demo | jq .
{
  "Critical": {
    "Identity": {
      "docker-reference": ""
    },
    "Image": {
      "Docker-manifest-digest": "97fc222cee7991b5b061d4d4afdb5f3428fcb0c9054e1690313786befa1e4e36"
    },
    "Type": "cosign container signature"
  },
  "Optional": {
    "sig": "original"
  }
}

# Now give that signature a memorable name, then sign that
$ crane tag $(cosign triangulate dlorenc/demo) mysignature
2021/02/15 20:22:55 dlorenc/demo:mysignature: digest: sha256:71f70e5d29bde87f988740665257c35b1c6f52dafa20fab4ba16b3b1f4c6ba0e size: 556
$ cosign sign -key cosign.key -a sig=counter dlorenc/demo:mysignature
Enter password for private key:
Pushing signature to: dlorenc/demo:sha256-71f70e5d29bde87f988740665257c35b1c6f52dafa20fab4ba16b3b1f4c6ba0e.cosign
$ cosign verify -key cosign.pub dlorenc/demo:mysignature
{"Critical":{"Identity":{"docker-reference":""},"Image":{"Docker-manifest-digest":"71f70e5d29bde87f988740665257c35b1c6f52dafa20fab4ba16b3b1f4c6ba0e"},"Type":"cosign container signature"},"Optional":{"sig":"counter"}}

# Finally, check the original signature
$ crane manifest dlorenc/demo@sha256:71f70e5d29bde87f988740665257c35b1c6f52dafa20fab4ba16b3b1f4c6ba0e
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
  "config": {
    "mediaType": "application/vnd.docker.container.image.v1+json",
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
