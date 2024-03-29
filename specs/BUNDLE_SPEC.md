# Cosign Bundle Specification

This document aims to describe how `cosign` attaches Sigstore attestation
[bundles](https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_bundle.proto)
to container images.

The goal is to specify the behavior well enough to promote other implementations
and enable interoperability. Attestations attached with `cosign` should be
retrievable in other tools, and vice-versa.

This document focuses on the layout of attestations within an
[OCI Image Manifest V1.1](https://github.com/opencontainers/image-spec/blob/v1.1.0/manifest.md)
object.

This document makes no assumptions about the contents of the Sigstore bundle.
Any attestation which can be represented as a Sigstore bundle (message
signatures, DSSE-wrapped in-toto statements, etc) can be attached to a container
image stored in an OCI registry.

Multiple Attestations may be "attached" to one image.

Attestations attached to a container image are generally assumed to refer to
that image in some way.

## Storage

The approach for storing Sigstore bundles in an OCI registry follows the
[guidelines for artifact usage](https://github.com/opencontainers/image-spec/blob/main/manifest.md#guidelines-for-artifact-usage)
in the OCI
[image spec](https://github.com/opencontainers/image-spec/blob/main/README.md).

### Publishing

First, the bundle itself is stored in its JSON-serialized form as a blob in the
registry:

```
POST /v2/foo/blobs/uploads/?digest=cafed00d...
Content-Type: application/octet-stream

{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json", ...}
```

In this example “foo” is the name of the repository within the registry to which
the artifact is being uploaded. The digest included as part of the POST is the
hex-encoded SHA-256 digest of the raw bytes of the bundle itself.

Once the blob has been created, the next step is to create a manifest that
associates the bundle blob with the image it describes:

```
PUT /v2/foo/manifests/sha256:badf00d...
Content-Type: application/vnd.oci.image.manifest.v1+json

{
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "schemaVersion": 2,
  "artifactType": "application/vnd.dev.sigstore.bundle.v0.3+json",
  "config": {
    "mediaType": "application/vnd.oci.empty.v1+json",
    "digest": "sha256:44136fa3...",
    "size": 2
  },
  "layers": [
    {
      "digest": "sha256:cafed00d...",
      "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
      "size": 4971
    }
  ],
  "subject": {
    "digest": "sha256:c00010ff...",
    "mediaType": "application/vnd.oci.image.index.v1+json"
   }
}
```

The manifest must have an `artifactType` field which identifies the type of the
artifact being referenced -- in this case, it's the Sigstore bundle media type.

The `layers` collection will have a single entry that points to the bundle's
blob by referencing its size, digest and media type.

The `subject` field associates this artifact with some other artifact which
already exists in this repository (in this case, an image with the digest
`c00010ff`)

Sigstore bundles don't require any additional configuration data, so the
`config` field references the
[empty descriptor](https://github.com/opencontainers/image-spec/blob/f5f87016de46439ccf91b5381cf76faaae2bc28f/manifest.md#guidance-for-an-empty-descriptor).

At this point, any registry which supports the
[referrers API](https://github.com/opencontainers/distribution-spec/blob/main/spec.md#listing-referrers)
will automatically associate this manifest with the listed subject and make it
available in the referrers index for that subject.

If the registry DOES NOT support the referrers API, a referrers list must be
manually created/updated using the
[referrers tag scheme](https://github.com/opencontainers/distribution-spec/blob/main/spec.md#referrers-tag-schema).

```
PUT /v2/foo/manifests/sha256-c00010ff...
Content-Type: application/vnd.oci.image.index.v1+json

{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.index.v1+json",
  "manifests": [
    {
      "mediaType": "application/vnd.oci.image.manifest.v1+json",
      "digest": "sha256:badf00d..",
      "size": 779,
      "artifactType": "application/vnd.dev.sigstore.bundle.v0.3+json"
    }
  ]
}
```

This index is uploaded with a tag that references the digest of the image to
which all of the listed artifacts are associated. Each of the items in the
`manifests` collection points to some other related artifact.

### Retrieval

When a client wants to locate Sigstore bundles which may be associated with a
given image, they would first make a request to
[referrers API](https://github.com/opencontainers/distribution-spec/blob/main/spec.md#listing-referrers)
with the image's digest:

```
GET /v2/foo/referrers/sha256:c000100ff...
```

A `404 Not Found` response indicates that the registry does not support the
referrers API and the referrers tag scheme should be used as a fallback:

```
GET /v2/foo/manifests/sha256-c000100ff...
```

A `404` here would indicate that there are no artifacts associated with the
image.

Assuming there are artifacts present, one of the two above calls will return an
image index listing the artifacts which have been associated with the specified
image:

```
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.index.v1+json",
  "manifests": [
    {
      "mediaType": "application/vnd.oci.image.manifest.v1+json",
      "digest": "sha256:badf00d..",
      "size": 779,
      "artifactType": "application/vnd.dev.sigstore.bundle.v0.3+json"
    }
  ]
}
```

From this the client can identify any Sigstore bundles by looking at the
`artifactType` field.

Using the `digest` listed in the image index, the next step is to retrieve the
manifest for the bundle:

```
GET /v2/foo/manifests/sha256:badf00d..
```

```
{
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "schemaVersion": 2,
  "artifactType": "application/vnd.dev.sigstore.bundle.v0.3+json",
  "config": {
    "mediaType": "application/vnd.oci.empty.v1+json",
    "digest": "sha256:44136fa3...",
    "size": 2
  },
  "layers": [
    {
      "digest": "sha256:cafed00d...",
      "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
      "size": 4971
    }
  ],
  "subject": {
    "digest": "sha256:c00010ff...",
    "mediaType": "application/vnd.oci.image.index.v1+json"
   }
}
```

The final step is to use the `digest` from the first of the `layers` to retrieve
the bundle blob:

```
GET /v2/foo/blobs/uploads/?digest=cafed00d...
```

```
{
  "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
  "verificationMaterial": {...},
  "messageSignature": {...}
}
```

## Annotations

For any given image, there may be any number of attached attestation bundles.
When there are multiple Sigstore bundles associated with an image it may be
difficult to identify which artifact is which in the image index:

```json
{
  "mediaType": "application/vnd.oci.image.index.v1+json",
  "schemaVersion": 2,
  "manifests": [
    {
      "artifactType": "application/vnd.dev.sigstore.bundle.v0.3+json",
      "digest": "sha256:facefeed",
      "mediaType": "application/vnd.oci.image.manifest.v1+json"
    },
    {
      "artifactType": "application/vnd.dev.sigstore.bundle.v0.3+json",
      "digest": "sha256:d0d0caca",
      "mediaType": "application/vnd.oci.image.manifest.v1+json"
    }
  ]
}
```

To help disambiguate attestations, clients may add annotations to the items in
the `manifests` list which indicate what is contained within each bundle and
when it was created:

- `dev.sigstore.bundle.content` - Must be one "message-signature" or
  "dsse-envelope" and should match the type of content embedded in the Sigstore
  bundle.
- `dev.sigstore.bundle.predicateType` - When the bundle contains a DSSE-wrapped
  in-toto statement, the statement's predicate can be reflected here.
- `org.opencontainers.image.created` - Date and time when the attestation bundle
  was created, conforming to
  [RFC 3339](https://tools.ietf.org/html/rfc3339#section-5.6) (this is one of
  the pre-defined annotation keys identified in the
  [OCI spec](https://github.com/opencontainers/image-spec/blob/main/annotations.md#pre-defined-annotation-keys)).

These annotations should be included as part of the bundle manifest:

```json
{
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "schemaVersion": 2,
  "artifactType": "application/vnd.dev.sigstore.bundle.v0.3+json",
  "annotations": {
    "dev.sigstore.bundle.content": "dsse-envelope",
    "dev.sigstore.bundle.predicateType": "https://slsa.dev/provenance/v1",
    "org.opencontainers.image.created": "2024-03-08T18:18:20.406Z"
  },
  "config": {
    "mediaType": "application/vnd.oci.empty.v1+json",
    "digest": "sha256:44136fa3...",
    "size": 2
  },
  "layers": [
    {
      "digest": "sha256:cafed00d...",
      "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
      "size": 4971
    }
  ],
  "subject": {
    "digest": "sha256:c00010ff...",
    "mediaType": "application/vnd.oci.image.index.v1+json"
  }
}
```

Registries which support the referrers API will automatically propagate any
annotations on the referring manifest to the index. For registries which do NOT
support the referrers API, the annotations should be added to the index when it
is updated manually. In either case, the end result should look something like
the following:

```json
{
  "mediaType": "application/vnd.oci.image.index.v1+json",
  "schemaVersion": 2,
  "manifests": [
    {
      "artifactType": "application/vnd.dev.sigstore.bundle.v0.3+json",
      "digest": "sha256:facefeed",
      "mediaType": "application/vnd.oci.image.manifest.v1+json",
      "annotations": {
        "dev.sigstore.bundle.content": "message-signature",
        "org.opencontainers.image.created": "2024-03-07T18:17:38.000Z"
      }
    },
    {
      "artifactType": "application/vnd.dev.sigstore.bundle.v0.3+json",
      "digest": "sha256:d0d0caca",
      "mediaType": "application/vnd.oci.image.manifest.v1+json",
      "annotations": {
        "dev.sigstore.bundle.content": "dsse-envelope",
        "dev.sigstore.bundle.predicateType": "https://slsa.dev/provenance/v1",
        "org.opencontainers.image.created": "2024-03-08T18:18:20.406Z"
      }
    }
  ]
}
```
