# Cosign Generic Predicate Specification

`Cosign` supports working with [In-Toto Attestations](https://github.com/in-toto/attestation) using the predicate model.
Several well-known predicates are supported natively, but `cosign` also supports a simple, generic, format for data that
doesn't fit well into other types.

The format for this is defined as follows:

`data`: Raw data to place in the attestation. This is a base64-encoded string of bytes.
`timestamp`: The timestamp the attestion was generated at in the RFC3339 format in the UTC timezone.

Here is an example attestation containing a data file containing `foo`:

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "cosign.sigstore.dev/attestation/v1",
  "subject": [
    {
      "name": "us.gcr.io/dlorenc-vmtest2/demo",
      "digest": {
        "sha256": "124e1fdee94fe5c5f902bc94da2d6e2fea243934c74e76c2368acdc8d3ac7155"
      }
    }
  ],
  "predicate": {
    "Data": "foo\n",
    "Timestamp": "2021-08-11T14:51:09Z"
  }
}
```