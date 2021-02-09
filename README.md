# cosign

Container Signing, Verification and Storage in an OCI registry.

## Installation

For now, clone and `go build -o cosign ./cmd`.
I'll publish releases when I'm comfortable supporting this for others to use.

## Quick Start

This shows how to:

* generate a keypair
* sign a container image and store that signature in the registry
* find signatures for a container image, and verify them against a public key

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
$ cosign sign -key cosign.key us-central1-docker.pkg.dev/dlorenc-vmtest2/test/taskrun
Enter password for private key:
Pushing signature to: us-central1-docker.pkg.dev/dlorenc-vmtest2/test/taskrun:sha256-87ef60f558bad79beea6425a3b28989f01dd417164150ab3baab98dcbf04def8
```

### Verify a container against a public key

This command returns 0 if *at least one* `cosign` formatted signature for the image is found
matching the public key.
See the detailed usage below for information and caveats on other signature formats.

Any valid payloads are printed to stdout, in json format.
Note that these signed payloads include the digest of the container image, which is how we can be
sure these "detached" signatures cover the correct image.

```
$ cosign verify -key public-key.pem us-central1-docker.pkg.dev/dlorenc-vmtest2/test/taskrun
{"Critical":{"Identity":{"docker-reference":""},"Image":{"Docker-manifest-digest":"87ef60f558bad79beea6425a3b28989f01dd417164150ab3baab98dcbf04def8"},"Type":""},"Optional":null}
```

## Detailed Usage

### Sign a container multiple times

Multiple signatures can be "attached" to a single container image:

```
$ cosign sign -key cosign.key us-central1-docker.pkg.dev/dlorenc-vmtest2/test/taskrun
Enter password for private key:
Pushing signature to: us-central1-docker.pkg.dev/dlorenc-vmtest2/test/taskrun:sha256-87ef60f558bad79beea6425a3b28989f01dd417164150ab3baab98dcbf04def8

$ cosign sign -key other-cosign.key us-central1-docker.pkg.dev/dlorenc-vmtest2/test/taskrun
Enter password for private key:
Pushing signature to: us-central1-docker.pkg.dev/dlorenc-vmtest2/test/taskrun:sha256-87ef60f558bad79beea6425a3b28989f01dd417164150ab3baab98dcbf04def8
```

We only actually sign the digest, but you can pass by tag or digest:

```
$ cosign sign -key other-cosign.key us-central1-docker.pkg.dev/dlorenc-vmtest2/test/taskrun:v1
Enter password for private key:
Pushing signature to: us-central1-docker.pkg.dev/dlorenc-vmtest2/test/taskrun:sha256-87ef60f558bad79beea6425a3b28989f01dd417164150ab3baab98dcbf04def8

$ cosign sign -key other-cosign.key us-central1-docker.pkg.dev/dlorenc-vmtest2/test/taskrun:v1
Enter password for private key:
Pushing signature to: us-central1-docker.pkg.dev/dlorenc-vmtest2/test/taskrun:sha256-87ef60f558bad79beea6425a3b28989f01dd417164150ab3baab98dcbf04def8
```

The `-a` flag can be used to add annotations to the generated, signed payload.
This flag can be repeated:

```
$ cosign sign -key cosign.key -a foo=bar -a baz=bat us-central1-docker.pkg.dev/dlorenc-vmtest2/test/taskrun:v1
Enter password for private key:
Pushing signature to: us-central1-docker.pkg.dev/dlorenc-vmtest2/test/taskrun:sha256-87ef60f558bad79beea6425a3b28989f01dd417164150ab3baab98dcbf04def8
```

These values are included in the signed payload under the `Optional` section.
(More on this later):

```
"Optional":{"baz":"bat","foo":"bar"}
```

### Sign and upload a generated payload (in another format, from another tool)

The payload must be specified as a path to a file:

```
$ cosign sign -key key.pem -payload payload.json us-central1-docker.pkg.dev/dlorenc-vmtest2/test/taskrun
Qr883oPOj0dj82PZ0d9mQ2lrdM0lbyLSXUkjt6ejrxtHxwe7bU6Gr27Sysgk1jagf1htO/gvkkg71oJiwWryCQ==
Using payload from: payload.json
Enter password for private key:
Pushing signature to: us-central1-docker.pkg.dev/dlorenc-vmtest2/test/taskrun:sha256-87ef60f558bad79beea6425a3b28989f01dd417164150ab3baab98dcbf04def8
```

### Sign but skip upload (to store somewhere else)

The base64 encoded signature is printed to stdout.
This can be stored somewhere else.

```
$ cosign sign -key key.pem --upload=false us-central1-docker.pkg.dev/dlorenc-vmtest2/test/taskrun
Qr883oPOj0dj82PZ0d9mQ2lrdM0lbyLSXUkjt6ejrxtHxwe7bU6Gr27Sysgk1jagf1htO/gvkkg71oJiwWryCQ==
```

### Generate the signature payload (to sign with another tool)

The json payload is printed to stdout:

```
$ cosign generate us-central1-docker.pkg.dev/dlorenc-vmtest2/test/taskrun
{"Critical":{"Identity":{"docker-reference":""},"Image":{"Docker-manifest-digest":"87ef60f558bad79beea6425a3b28989f01dd417164150ab3baab98dcbf04def8"},"Type":""},"Optional":null}
```

This can be piped directly into openssl:

```
$ cosign generate us-central1-docker.pkg.dev/dlorenc-vmtest2/test/taskrun | openssl...
```

### Upload a generated signature

The signature is passed via the -signature flag.
It can be a file:

```
$ cosign upload -signature file.sig us-central1-docker.pkg.dev/dlorenc-vmtest2/test/taskrun
Pushing signature to: us-central1-docker.pkg.dev/dlorenc-vmtest2/test/taskrun:sha256-87ef60f558bad79beea6425a3b28989f01dd417164150ab3baab98dcbf04def8
```

the base64-encoded signature:

```
$ cosign upload -signature Qr883oPOj0dj82PZ0d9mQ2lrdM0lbyLSXUkjt6ejrxtHxwe7bU6Gr27Sysgk1jagf1htO/gvkkg71oJiwWryCQ== us-central1-docker.pkg.dev/dlorenc-vmtest2/test/taskrun
Pushing signature to: us-central1-docker.pkg.dev/dlorenc-vmtest2/test/taskrun:sha256-87ef60f558bad79beea6425a3b28989f01dd417164150ab3baab98dcbf04def
```

or, `-` for stdin for chaining from other commands:

```
$ cosign generate us-central1-docker.pkg.dev/dlorenc-vmtest2/test/taskrun | openssl... | cosign upload -signature -- us-central1-docker.pkg.dev/dlorenc-vmtest2/test/taskrun
Pushing signature to: us-central1-docker.pkg.dev/dlorenc-vmtest2/test/taskrun:sha256-87ef60f558bad79beea6425a3b28989f01dd417164150ab3baab98dcbf04def
```

### Verifying claims

**Important Note**:

Signature payloads created by `cosign` included the digest of the container image they are attached to.
By default, `cosign` validates that this digest matches the container during `cosign verify`.

If you are using other payload formats with `cosign`, you can use the `-check-claims=false` flag:

```
$ cosign verify -check-claims=false -key public-key.pem us-central1-docker.pkg.dev/dlorenc-vmtest2/test/taskrun
Warning: the following claims have not been verified:
{"Critical":{"Identity":{"docker-reference":""},"Image":{"Docker-manifest-digest":"87ef60f558bad79beea6425a3b28989f01dd417164150ab3baab98dcbf04def8"},"Type":"cosign container signature"},"Optional":null}
```

This will still verify the signature and payload against the supplied public key, but will not
verify any claims in the payload.

### Download the signatures to verify with another tool

Each signature is printed to stdout in a json format:

```
$ cosign download us-central1-docker.pkg.dev/dlorenc-vmtest2/test/taskrun
{"Base64Signature":"Ejy6ipGJjUzMDoQFePWixqPBYF0iSnIvpMWps3mlcYNSEcRRZelL7GzimKXaMjxfhy5bshNGvDT5QoUJ0tqUAg==","Payload":"eyJDcml0aWNhbCI6eyJJZGVudGl0eSI6eyJkb2NrZXItcmVmZXJlbmNlIjoiIn0sIkltYWdlIjp7IkRvY2tlci1tYW5pZmVzdC1kaWdlc3QiOiI4N2VmNjBmNTU4YmFkNzliZWVhNjQyNWEzYjI4OTg5ZjAxZGQ0MTcxNjQxNTBhYjNiYWFiOThkY2JmMDRkZWY4In0sIlR5cGUiOiIifSwiT3B0aW9uYWwiOm51bGx9"}
```

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

Public keys are stored on disk in PEM format with a header of `COSIGN PUBLIC KEY`.
```
-----BEGIN COSIGN PUBLIC KEY-----
NqfC4CpZiE4OGpuYFSSMzXHJqXQ6u1W55prrZIjjZJ0=
-----END COSIGN PUBLIC KEY-----
```

The inner (base64 encoded) data portion can be supplied directly on the command line without the PEM blocks:

```
$ cosign verify -key NqfC4CpZiE4OGpuYFSSMzXHJqXQ6u1W55prrZIjjZJ0= us-central1-docker.pkg.dev/dlorenc-vmtest2/test/taskrun
```

## Storage Specification

`cosign ` stores signatures in an OCI registry, and uses a naming convention (tag based
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

## Caveats

`cosign` only generates Ed25519 keys with SHA256 hashes.
Keys are stored in PEM-encoded PKCS8 format.
However, you can use `cosign` to store and retrieve signatures in any format, from any algorithm.

`cosign` does not handle key-distribution or PKI.

`cosign` does not handle key-management or storage.
There are no keyrings or local state.

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


`cosign` signatures are stored as separate objects in the OCI registry, with only a weak
reference back to the object they "sign".
This means this relationship is opaque to the registry, and signatures *will not* be deleted
or garbage-collected when the image is deleted.
Similarly, they **can** easily be copied from one environment to another, but this is not
automatic.

Multiple signatures are stored in a list which is unfortunately "racy" today.
To add a signtaure, clients orchestrate a "read-append-write" operation, so the last write
will win in the case of contention.

`cosign` has been tested, barely, against GCP's Artifact Registry (pkg.dev).
`cosign` uses [go-containerregistry](github.com/google/go-containerregistry) for registry
interactions, which has excellent support, but other registries may have quirks.

## FAQ

### Who is using this?

Hopefully no one yet. Stay tuned, though.

### Why not use Notary v2

### Why not use containers/image signing

`containers/image` signing is close to `cosign`, and we reuse payload formats.
`cosign` differs in that it signs with ED25519 keys instead of PGP, and stores
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
