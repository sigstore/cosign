# Sigstore bundle

Authors: @kommendorkapten, @patflynn

This directory (`sigstore_bundle`) is only temporary for a discussion.
It will be removed later and all files put into their correct places.

This specification captures the MVP set of features from this
[proposal](https://docs.google.com/document/d/1gucjOA_bGyRjK6TeaOI-X5GIUv8WsPzeMDMkq25Kv4Y/).
There are more features discussed in that proposal that are not
covered here. We believe that this slimmed down proposal covers the
imminent need. Getting agreement on this would so enable a solid
foundation from where the discussion can continue, covering more
functionality and possible simplifications on the Rekor side.

Included are formal [definitions](pb/) of the bundle format (protobuf),
relying on the DSSE protobuf
[definition](https://github.com/secure-systems-lab/dsse/blob/9c813476bd36de70a5738c72e784f123ecea16af/envelope.proto),
and some example JSON encodings.

In [verification_flows.md](verification_flows.md) some test cases are
discussed, to ensure that the functionality works as expected.
