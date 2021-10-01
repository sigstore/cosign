# Detailed Usage

## Sign a container multiple times

Multiple signatures can be "attached" to a single container image:

```shell
$ cosign sign --key cosign.key dlorenc/demo
Enter password for private key:
Pushing signature to: index.docker.io/dlorenc/demo:sha256-87ef60f558bad79beea6425a3b28989f01dd417164150ab3baab98dcbf04def8.sig

$ cosign sign --key other.key dlorenc/demo
Enter password for private key:
Pushing signature to: index.docker.io/dlorenc/demo:sha256-87ef60f558bad79beea6425a3b28989f01dd417164150ab3baab98dcbf04def8.sig
```

We only actually sign the digest, but you can pass by tag or digest.

The `-a` flag can be used to add annotations to the generated, signed payload.
This flag can be repeated:

```shell
$ cosign sign --key other.key -a foo=bar dlorenc/demo
Enter password for private key:
Pushing signature to: index.docker.io/dlorenc/demo:sha256-87ef60f558bad79beea6425a3b28989f01dd417164150ab3baab98dcbf04def8.sig
```

These values are included in the signed payload under the `Optional` section.
(More on this later):

```json
"Optional":{"baz":"bat","foo":"bar"}
```

they can be verified with the `-a` flag to `cosign verify`.

## Sign and upload a generated payload (in another format, from another tool)

The payload must be specified as a path to a file:

```shell
$ cosign sign --key cosign.key --payload README.md dlorenc/demo
Using payload from: README.md
Enter password for private key:
Pushing signature to: index.docker.io/dlorenc/demo:sha256-87ef60f558bad79beea6425a3b28989f01dd417164150ab3baab98dcbf04def8.sig
```

## Signature Location and Management

Signatures are uploaded to an OCI artifact stored with a predictable name.
This name can be located with the `cosign triangulate` command:

```shell
cosign triangulate dlorenc/demo
index.docker.io/dlorenc/demo:sha256-87ef60f558bad79beea6425a3b28989f01dd417164150ab3baab98dcbf04def8.sig
```

They can be viewed with `crane`:

```shell
crane manifest $(cosign triangulate gcr.io/dlorenc-vmtest2/demo) | jq .
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
  "config": {
    "mediaType": "application/vnd.docker.container.image.v1+json",
    "size": 342,
    "digest": "sha256:f5de0db6e714055d48b4bb3a374e9630c4923fa704d9311da6a2740cf625aaba"
  },
  "layers": [
    {
      "mediaType": "application/vnd.dev.cosign.simplesigning.v1+json",
      "size": 210,
      "digest": "sha256:1119abab63e605dcc281019bad0424744178b6f61ba57378701fe7391994c999",
      "annotations": {
        "dev.cosignproject.cosign/signature": "MEUCIG0ZmgqE3qTrHWp+HF9CrxsNH57Cck3cQI+zNNrUwSHfAiEAm+2eY/Z6ixQwjLbTraDN5ZB/P1Z5k/KwIoblry65r+s="
      }
    },
    {
      "mediaType": "application/vnd.dev.cosign.simplesigning.v1+json",
      "size": 219,
      "digest": "sha256:583246418c2afd5bfe29694793d07da37ffd552aadf8879b1d98047178b80398",
      "annotations": {
        "dev.cosignproject.cosign/signature": "MEUCIF/+szLKKA2q2+c86AXeWR7UeD5yYpW7p0waHordxNjhAiEAm5e+Hm7Jhv9JpSwHpTc6aGLSkL6/Acm/z+b8mhfGXqY="
      }
    }
  ]
}
```

Some registries support deletion too (DockerHub does not):

```shell
$ cosign clean gcr.io/dlorenc-vmtest2/demo
```

## Sign but skip upload (to store somewhere else)

The base64 encoded signature is printed to stdout.
This can be stored somewhere else.

```shell
$ cosign sign --key key.pem --upload=false dlorenc/demo
Qr883oPOj0dj82PZ0d9mQ2lrdM0lbyLSXUkjt6ejrxtHxwe7bU6Gr27Sysgk1jagf1htO/gvkkg71oJiwWryCQ==
```

## Generate the signature payload (to sign with another tool)

The json payload is printed to stdout:

```shell
$ cosign generate dlorenc/demo
{"Critical":{"Identity":{"docker-reference":""},"Image":{"Docker-manifest-digest":"87ef60f558bad79beea6425a3b28989f01dd417164150ab3baab98dcbf04def8"},"Type":"cosign container image signature"},"Optional":null}
```

This can be piped directly into openssl:

```shell
$ cosign generate dlorenc/demo | openssl...
```

## Upload a generated signature

The signature is passed via the `--signature` flag.
It can be a file:

```shell
$ cosign attach signature --signature file.sig dlorenc/demo
Pushing signature to: dlorenc/demo:sha256-87ef60f558bad79beea6425a3b28989f01dd417164150ab3baab98dcbf04def8.sig
```

the base64-encoded signature:

```shell
$ cosign attach signature --signature Qr883oPOj0dj82PZ0d9mQ2lrdM0lbyLSXUkjt6ejrxtHxwe7bU6Gr27Sysgk1jagf1htO/gvkkg71oJiwWryCQ== dlorenc/demo
Pushing signature to: dlorenc/demo:sha256-87ef60f558bad79beea6425a3b28989f01dd417164150ab3baab98dcbf04def.sig
```

or, `-` for stdin for chaining from other commands:

```shell
$ cosign generate dlorenc/demo | openssl... | cosign attach signature --signature -- dlorenc/demo
Pushing signature to: dlorenc/demo:sha256-87ef60f558bad79beea6425a3b28989f01dd417164150ab3baab98dcbf04def.sig
```

## Verifying claims

**Important Note**:

Signature payloads created by `cosign` included the digest of the container image they are attached to.
By default, `cosign` validates that this digest matches the container during `cosign verify`.

If you are using other payload formats with `cosign`, you can use the `--check-claims=false` flag:

```shell
$ cosign verify --check-claims=false --key cosign.pub dlorenc/demo
Warning: the following claims have not been verified:
{"Critical":{"Identity":{"docker-reference":""},"Image":{"Docker-manifest-digest":"87ef60f558bad79beea6425a3b28989f01dd417164150ab3baab98dcbf04def8"},"Type":"cosign container image signature"},"Optional":null}
```

This will still verify the signature and payload against the supplied public key, but will not
verify any claims in the payload.

Annotations made in the original signature (`cosign sign -a foo=bar`) are present under the `Optional` section of the payload:

```shell
$ cosign verify --key cosign.pub  dlorenc/demo | jq .
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

These can be checked with matching `-a foo=bar` flags on `cosign verify`.
When using this flag, **every** specified key-value pair **must exist and match** in the verified payload.
The payload may contain other key-value pairs.

```shell
# This works
$ cosign verify -a --key cosign.pub  dlorenc/demo
{"Critical":{"Identity":{"docker-reference":""},"Image":{"Docker-manifest-digest":"97fc222cee7991b5b061d4d4afdb5f3428fcb0c9054e1690313786befa1e4e36"},"Type":"cosign container image signature"},"Optional":{"sig":"original"}}

# This works too
$ cosign verify -a sig=original --key cosign.pub  dlorenc/demo
{"Critical":{"Identity":{"docker-reference":""},"Image":{"Docker-manifest-digest":"97fc222cee7991b5b061d4d4afdb5f3428fcb0c9054e1690313786befa1e4e36"},"Type":"cosign container image signature"},"Optional":{"sig":"original"}}

# This doesn't work
$ cosign verify -a sig=original -a=foo=bar --key cosign.pub  dlorenc/demo
error: no matching claims:
invalid or missing annotation in claim: map[sig:original]
```

## Download the signatures to verify with another tool

Each signature is printed to stdout in a json format:

```
$ cosign download signature us-central1-docker.pkg.dev/dlorenc-vmtest2/test/taskrun
{"Base64Signature":"Ejy6ipGJjUzMDoQFePWixqPBYF0iSnIvpMWps3mlcYNSEcRRZelL7GzimKXaMjxfhy5bshNGvDT5QoUJ0tqUAg==","Payload":"eyJDcml0aWNhbCI6eyJJZGVudGl0eSI6eyJkb2NrZXItcmVmZXJlbmNlIjoiIn0sIkltYWdlIjp7IkRvY2tlci1tYW5pZmVzdC1kaWdlc3QiOiI4N2VmNjBmNTU4YmFkNzliZWVhNjQyNWEzYjI4OTg5ZjAxZGQ0MTcxNjQxNTBhYjNiYWFiOThkY2JmMDRkZWY4In0sIlR5cGUiOiIifSwiT3B0aW9uYWwiOm51bGx9"}
```

## Retrieve the Public Key From a Private Key or KMS


KMS:
```shell
# Retrieve from Google Cloud KMS
$ cosign public-key --key gcpkms://projects/someproject/locations/us-central1/keyRings/foo/cryptoKeys/bug/versions/1
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgrKKtyws86/APoULh/zXk4LONqII
AcxvLtLEgRjRI4TKnMAXtIGp8K4X4CTWPEXMqSYZZUa2I1YvHyLLY2bEzA==
-----END PUBLIC KEY-----

# Retrieve from HashiCorp Vault
$ cosign public-key --key hashivault://transit
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgrKKtyws86/APoULh/zXk4LONqII
AcxvLtLEgRjRI4TKnMAXtIGp8K4X4CTWPEXMqSYZZUa2I1YvHyLLY2bEzA==
-----END PUBLIC KEY-----
```

Private Key:
```shell
$ ./cosign public-key --key cosign.key
Enter password for private key:
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjCxhhvb1KmIfe1J2ceT25kHepstb
IDYuTA0U1ri4F0CXXazLiftzGlyfse1No4orr8w1ZIchQ8TJlyCSaSuR0Q==
-----END PUBLIC KEY-----
```

# Experimental Features

## Verify a signature was added to the transparency log
There are two options for verifying a cosign signature was added to a transparency log:
1. Check the log to make sure the entry exists in the log
2. Use the `bundle` annotation on a cosign signature to verify an element was added to the log without hitting the log

The cosign `bundle` annotation contains a Signed Entry Timestamp (SET), which is conceptually similar to an SCT in a Web PKI system.
The SET is a signed inclusion promise provided by the transparency log, which acts as a guarantee by the log that an element has been included in it.
The SET can be verified with the logs public key and used to prove that an element is in the log without actually checking the log itself.

For more details on how the `bundle` annotation is formatted, see the cosign [spec](SPEC.md).

To verify the `bundle` annotation, follow these steps:
1. Marshal the `bundle` Payload into JSON
1. Canonicalize the payload by following RFC 8785 rules
1. Verify the canonicalized payload and signedEntryTimestamp against the transparency logs public key
