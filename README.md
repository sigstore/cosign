# cosign

Container Signing, Verification and Storage in an OCI registry.

### Installation

TODO

## Usage


### Generate a keypair

```
$ cosign generate-key-pair
```

### Signing

#### Sign a container and store the signature in the registry

```
$ cosign sign -key private-key.pem gcr.io/dlorenc-vmtest2/foo
```

This can be done multiple times:

```
$ cosign sign -key private-key.pem gcr.io/dlorenc-vmtest2/foo
$ cosign sign -key other-private-key.pem gcr.io/dlorenc-vmtest2/foo
```

We only actually sign the digest, but you can pass by tag or digest:

```
cosign sign -key other-private-key.pem gcr.io/dlorenc-vmtest2/foo:v1
cosign sign -key other-private-key.pem gcr.io/dlorenc-vmtest2/foo@sha256:dfda
```

#### Sign but skip upload

```
$ cosign sign -key key.pem gcr.io/dlorenc-vmtest2/foo --no-upload
```

#### Generate the signature payload, to sign with another tool

```
$ cosign generate gcr.io/dlorenc-vmtest2/foo
```

This can be piped directly into openssl:

```
$ cosign generate gcr.io/dlorenc-vmtest2/foo | openssl...
```

#### Upload a generated signature

```
$ cosign upload -signature sig gcr.io/dlorenc-vmtest2/foo
```

This can read from stdin if you want to chain from the generate command:

```
$ cosign generate gcr.io/dlorenc-vmtest2/foo | openssl... | cosign upload -signature -- gcr.io/dlorenc-vmtest2/foo
```

### Verification

#### Verify a container against a public key

```
# Returns 0 if *at least one* signature for the image is found matching the public key.
$ cosign verify -key public-key.pem gcr.io/dlorenc-vmtest2/foo
```

#### Download the signatures to verify with another tool

```
$ cosign download gcr.io/dlorenc-vmtest2/foo
```

These can be piped to openssl:

```
$ cosign download gcr.io/dlorenc-vmtest2/foo | openssl...
```

or to a remote KMS:
```
$ cosign download gcr.io/dlorenc-vmtest2/foo | gcloud kms asymetric-sign...
```

#### Verify a downloaded signature

```
$ cosine verify -key public-key.pem -signature sig <image>
```

## Signature Specification

`cosine is inspired by tools like [minisign](https://jedisct1.github.io/minisign/) and
[signify](https://www.openbsd.org/papers/bsdcan-signify.html).


### Caveats

`cosine` only supports Ed25519 keys with SHA256 hashes.
Keys are stored in PEM-encoded PKCS8 format.

`cosine` does not handle key-distribution or PKI.

`cosine` does not handle key-management or storage.
There are no keyrings or local state.

`cosine` only supports Red Hat's [simple signing](https://www.redhat.com/en/blog/container-image-signing)
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
           "type": "cosine container signature"
    },
    "optional": {
           "creator": "atomic",
           "timestamp": 1458239713
    }
}
```

**Note:** This can be generated for an image reference using `cosine generate <image>`.

## Storage Specification

add jon's diagram

## FAQ

### Who is using this?

Hopefully no one yet. Stay tuned, though.

### Why not use Notary v2

### Why not use containers/image signing

`containers/image` signing is close to `cosine`, and we reuse payload formats.
`cosine` differs in that it signs with ED25519 keys instead of PGP, and stores
signatures in the registry.

### Why not use TUF?

I believe this tool is complementary to TUF, and they can be used together.
I haven't tried yet, but think we can also reuse a registry for TUF storage.

### Why not use Blockchain?

Just kidding. Nobody actually asked this.

### Why not use $FOO?

See the next section, [Requirements].
I designed this tool to meet a few specific requirements, and didn't find
anything else that met all of these.
If you're aware of another system that does meet these, please let me know!

## Requirements

* No external services for signature storage, querying, or retrieval
* Everything should work over the registry API
* PGP should not be required at all. 
* Users must be able to find all signatures for an image
* Signers can sign an image after push
* Multiple entities can sign an image
* Signing an image does not mutate the image
* Pure-go implementation
