# Cosign SBOM Specifications

This document aims to describe how `cosign` attaches SBOM (Software Bill of Materials) documents to containers.

The goal is to specify the behavior well enough to promote other implementations and enable interoperability.
SBOMs attached with `cosign` should be retrievable in other tools, and vice-versa.

This document focuses on the layout of an SBOM within an [OCI Image Manifest V1](https://github.com/opencontainers/image-spec/blob/master/manifest.md) object.

This document does not prescribe any specific SBOM format.
Multiple formats can be used, and the `mediaType` property should describe the format of a particular SBOM document.

Multiple SBOMs may be "attached" to one image.
Each SBOM may refer to the entire image, or to a specific part of that image.
Exactly what the SBOM refers to is called the "scope" of that SBOM.

SBOMs stored in an OCI registry are generally assumed to refer to other objects stored in that same registry.
This document does not specify how these "links" are created.
A naming convention or the [in-progress OCI `references` API](https://github.com/opencontainers/image-spec/issues/827) are viable options.

This document does not specify how clients should behave When multiple SBOMs are present for an image.
Clients may list all the SBOMs, or may provide tooling to filter based on SBOM type or scope.

## Overall Layout

An SBOM object is represented an [OCI Image Manifest V1](https://github.com/opencontainers/image-spec/blob/master/manifest.md).

Each individual SBOM is represented as a `layer`, using a standard `descriptor`.
The `layers` list is ordered, but no order is assumed or important for the SBOM documents.

Here is an example manifest containing one SBOM, in the [SPDX](https://spdx.org) format:

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
      "mediaType": "text/spdx",
      "size": 246,
      "digest": "sha256:ed3ad03d3b87843b5419d7dce9d50a3e0f45554b2ba93bf378611cae6b450cff",
    }
  ]
}
```

Multiple SBOMs may be attached, using multiple formats.
This example shows two SBOMs, one in the SPDX format and one in the CycloneDX format:

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
      "mediaType": "text/spdx",
      "size": 246,
      "digest": "sha256:ed3ad03d3b87843b5419d7dce9d50a3e0f45554b2ba93bf378611cae6b450cff",
    },
    {
      "mediaType": "application/vnd.cyclonedx",
      "size": 462,
      "digest": "sha256:e0851a4aa13657fc8dcd01e0e5e08cb817123ccb82e2c604b34f9ec9c1755e3f",
    }
  ]
}
```

Each individual SBOM may also be "scoped" to a part of the object it refers to.
This is indicated via an annotation on the descriptor.
In this example, the SBOM only refers to a single layer:

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
      "mediaType": "text/spdx",
      "size": 246,
      "digest": "sha256:ed3ad03d3b87843b5419d7dce9d50a3e0f45554b2ba93bf378611cae6b450cff",
      "annotatons": {
        "dev.sigstore.sbom.scope": "layer=sha256:a69d803ab2179a570eda27135989ee850de53bbd98efc8f0284f13700a94149f",
      }
    }
  ]
}
```

## MediaTypes

The two main SBOM formats in use are [SPDX](https://spdx.org) and [CycloneDX](https://cyclonedx.org/).
The `mediaTypes` for these should be indicated in the `descriptor` for each `layer`.

The `mediaTypes` are:

* `application/vnd.cyclonedx`
* `text/spdx`

These `mediaTypes` can contain format-specific suffixes as well. For example:

* `application/vnd.cyclonedx+xml`
* `application/vnd.cyclonedx+json`
* `text/spdx+xml`
* `text/spdx+json`

## Scopes

SBOMs may refer to an entire object, or to a specific part of that object.
This is called the `scope` of the SBOM.

The `scope` should be indicated via an annotation on the `Descriptor`, with the key of `dev.sigstore.sbom.scope`.

A descriptor with no scope is assumed to refer to the entire object.
This is the same as the scope of `all`.

Well-known scopes include:

* `all`: the SBOM refers to the entire object.
* `layer=sha256:$DIGEST`: the SBOM refers to the layer with the appropriate digest.
* `path=<foo>`: the SBOM refers to file at path `foo` in the flattened image.

Scopes may be repeated, and are separated by the `,` character.
This scope refers to two layers: `layer=sha256:$DIGEST,layer=sha256:$OTHERDIGEST`

## Relationship

While SBOMs typically relate directly to the contents of the object they refer to, in certain circumstances they may instead relate to the object indirectly.
One exmaple here is that the SBOM could describe the environment the object was built in, rather than the contents of the object itself.
This type of relationship will be tracked by this spec somehow, but we're not sure exactly how yet.