# Cosign Attestation Specifications

This document aims to describe how `cosign` attaches `Attestations` to container images.

The goal is to specify the behavior well enough to promote other implementations and enable interoperability.
Attestations attached with `cosign` should be retrievable in other tools, and vice-versa.

This document focuses on the layout of attestations within an [OCI Image Manifest V1](https://github.com/opencontainers/image-spec/blob/master/manifest.md) object.

This document assumes you are using the In-Toto [Attestation](https://github.com/in-toto/attestation) format, serialized as a `DSSE` envelope
Other formats can be used, and the `mediaType` property should describe the format of a particular attestation, but implementations may not understand them.
The DSSE envelope format is defined [here](https://github.com/secure-systems-lab/dsse/blob/master/envelope.md#dsse-envelope) and uses the `mediaType`: `application/vnd.dsse.envelope.v1+json`.

Multiple Attestations may be "attached" to one image.
Each Attestation may refer to the entire image, or to a specific part of that image.
This is indicated via the `subject` field of the `Statement` inside the `Attestation`.

Attestations attached to a container image are generally assumed to refer to that image in some way.

## Overall Layout

An `Attestation` object is represented as an [OCI Image Manifest V1](https://github.com/opencontainers/image-spec/blob/master/manifest.md).

Each individual `Attestation` is represented as a `layer`, using a standard `descriptor`.
The `layers` list is ordered, but no order is assumed or important for the `Attestations`.

Here is an example manifest containing one `Attestation`:

```json
{
  "schemaVersion": 2,
  "config": {
    "mediaType": "application/vnd.oci.image.config.v1+json",
    "size": 233,
    "digest": "sha256:83bd5fb5b39f65f28e50a86d48fa79c07880befc292d92eebdc18531054b070c"
  },
  "layers": [
    {
      "mediaType": "application/vnd.dsse.envelope.v1+json",
      "size": 246,
      "digest": "sha256:ed3ad03d3b87843b5419d7dce9d50a3e0f45554b2ba93bf378611cae6b450cff",
    }
  ]
}
```

## Subject Verification

`Attestations` MAY refer to multiple `subjects`.

When verifying an attestation for a container image, implementations MUST verify the relationship between the `subject` field and the container image.
Attestations MAY reference the entire container image or a portion of it.

Implementations MUST support `Attestations` that reference the entire container image, other relationship types are optional.
