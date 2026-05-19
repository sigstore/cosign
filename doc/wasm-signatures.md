# WebAssembly Module Signing and Signature Management

This document describes cosign's WebAssembly-specific signing commands and the
embedded signature model used by `cosign wasm`. It is intended for users who
need a complete module-level signing workflow, similar in spirit to the way PE
files can carry signatures from one or more publishers while still remaining
directly executable by the platform loader.

The generated command reference pages under `doc/cosign_wasm*.md` list flags and
short examples. This document explains the signing format, multi-signature
semantics, operational workflows, and security considerations in more detail.

## Scope

The WebAssembly command group is designed for `.wasm` modules that should carry
their own Sigstore verification material inside the module file. The supported
operations are:

| Operation | Command | Purpose |
| --- | --- | --- |
| Sign a module | `cosign wasm sign <module> --wasm-output <file>` | Sign the canonical unsigned module bytes and append a new embedded signature section. |
| Verify embedded signatures | `cosign wasm verify <module>` | Verify every embedded signature bundle against the canonical unsigned module bytes. |
| List embedded signatures | `cosign wasm list-signatures <module>` | Show metadata for every embedded `wasm-cosign` section. |
| Extract embedded signatures | `cosign wasm extract-signatures <module>` | Print the raw embedded Sigstore bundle payloads. |
| Strip embedded signatures | `cosign wasm strip-signatures <module> -o <file>` | Remove every embedded `wasm-cosign` section and write the unsigned module. |

The lower-level blob commands also support the same WebAssembly payload rules:

| Blob command | WebAssembly-specific behavior |
| --- | --- |
| `cosign sign-blob --wasm --wasm-output <file> <module>` | Sign the canonical unsigned module and append the resulting bundle to the output module. |
| `cosign verify-blob --wasm <module>` | Verify the canonical unsigned module using either embedded bundles or explicitly supplied verification material. |

Use the `cosign wasm` command group for normal module signing workflows. Use
`sign-blob --wasm` and `verify-blob --wasm` when integrating with existing blob
signing automation.

## Embedded Signature Format

Cosign stores embedded WebAssembly signatures in a WebAssembly custom section
named:

```text
wasm-cosign
```

The section payload is the Sigstore bundle produced by cosign in the new bundle
format. WebAssembly runtimes ignore custom sections, so appending a
`wasm-cosign` custom section does not change the module's execution semantics.
The signed module remains a valid WebAssembly module and can be passed to a
runtime without removing the signature sections.

Only custom sections with exactly the name `wasm-cosign` are treated as embedded
cosign signatures. Other custom sections, such as `name`, `producers`, or
toolchain-specific metadata sections, are preserved as normal module bytes.

## Canonical Signing Payload

Cosign does not sign the raw `.wasm` file bytes after the signature section has
been added. That would be self-referential: the signature would need to cover
the bytes that contain the signature itself. Instead, the WebAssembly-specific
payload is the module with every embedded cosign signature section removed.

The canonical payload is computed as follows:

1. Read the WebAssembly module.
2. Validate the WebAssembly magic header and supported version.
3. Iterate through all module sections in file order.
4. Remove every custom section whose name is exactly `wasm-cosign`.
5. Preserve all other bytes exactly as they appeared in the module.
6. Sign or verify the resulting byte sequence.

Conceptually, this is equivalent to concatenating all byte ranges that are not
`wasm-cosign` custom sections, in their original order. The implementation may
materialize those canonical bytes before signing or verifying, but the security
property is the same: the signature covers the complete module except for the
embedded signature containers themselves.

This rule has several important consequences:

| Change to the module | Effect on existing embedded signatures |
| --- | --- |
| Add another `wasm-cosign` section | Existing signatures remain valid. |
| Remove one or more `wasm-cosign` sections | Remaining signatures remain valid. |
| Reorder `wasm-cosign` sections only | Signature payload is unchanged, but section indexes and offsets change. |
| Add, remove, or modify any non-signature section | Existing signatures fail verification. |
| Reorder non-signature sections | Existing signatures fail verification. |
| Change the WebAssembly code, data, imports, exports, or metadata | Existing signatures fail verification. |

This is the same high-level idea used by many embedded-signature file formats:
the signature storage area is excluded from the digest, while the executable
content and all non-signature metadata remain protected.

## Multi-Signature Semantics

Cosign supports multiple embedded signatures in one WebAssembly module. A module
may contain more than one `wasm-cosign` custom section. Those sections may be
located anywhere a valid WebAssembly custom section can appear, although the
cosign signing command appends new signatures to the end of the module.

Multi-signature behavior is intentionally additive:

| Action | Behavior |
| --- | --- |
| Sign an unsigned module | A new `wasm-cosign` custom section is appended. |
| Sign an already signed module | Existing `wasm-cosign` sections are preserved and another one is appended. |
| Verify a module with multiple embedded bundles | Every embedded bundle is verified against the same canonical unsigned payload. |
| Strip signatures | All `wasm-cosign` sections are removed. |
| List signatures | Each embedded section is reported with its index, offset, size, and payload digest. |
| Extract signatures | All embedded bundle payloads are emitted in section order. |

Because all `wasm-cosign` sections are excluded from the canonical payload, a
signature created by one vendor remains valid when another vendor appends a
second signature later. This allows workflows such as:

- An upstream language toolchain signs the module it produced.
- A security scanning service signs the same module after policy checks.
- A platform vendor signs the module after compatibility testing.
- An organization signs the module again during internal release promotion.

Each signature is independent verification material over the same protected
module payload. Cosign verifies cryptographic validity, transparency log
material, timestamps, certificates, and identity policy according to the flags
provided by the caller. Deciding which signers are required for a given
deployment is a policy decision for the verifier or release system.

## Signing Workflows

### Sign with a Local Key

Use `cosign wasm sign` to produce a signed module containing an embedded bundle:

```shell
cosign wasm sign \
  --key cosign.key \
  --wasm-output module.signed.wasm \
  module.wasm
```

The command signs the canonical unsigned payload and writes a new module to
`module.signed.wasm`. The original input file is not modified in place.

The command requires `--wasm-output`. This makes the output path explicit and
avoids accidentally replacing the input module.

### Sign with Keyless Sigstore Identity

The WebAssembly command reuses the same signing options as `sign-blob`. For a
keyless signing flow, omit `--key` and use the configured Fulcio/OIDC flow:

```shell
cosign wasm sign \
  --wasm-output module.signed.wasm \
  module.wasm
```

Depending on the environment, cosign may use ambient identity providers, an
interactive browser flow, a device flow, or an explicitly supplied identity
token. See the generated `cosign wasm sign` command reference for the full list
of OIDC, Fulcio, Rekor, signing-config, timestamp, and trusted-root flags.

### Append a Second Signature

To add a signature without removing existing signatures, sign the already signed
module and write a new output module:

```shell
cosign wasm sign \
  --key vendor-b.key \
  --wasm-output module.vendor-b.wasm \
  module.signed.wasm
```

Cosign signs the canonical payload obtained by removing all existing
`wasm-cosign` sections, then appends a new `wasm-cosign` section to the original
input module. The previous embedded signatures remain present in the output.

### Keep a Sidecar Bundle While Embedding

You may also ask cosign to write the bundle to a separate file while embedding
the same verification material in the module:

```shell
cosign wasm sign \
  --key cosign.key \
  --bundle module.bundle.json \
  --wasm-output module.signed.wasm \
  module.wasm
```

This is useful when a distribution channel wants the module to be self-contained
but a build system also wants to archive the bundle separately.

### Write the Signed Module to Standard Output

Use `--wasm-output -` to write the signed module bytes to standard output:

```shell
cosign wasm sign \
  --key cosign.key \
  --wasm-output - \
  module.wasm > module.signed.wasm
```

When writing binary module bytes to standard output, redirect output to a file or
pipe it into a tool that expects raw WebAssembly bytes.

### Compatibility Path Through sign-blob

The `sign-blob` command can be used directly with `--wasm`:

```shell
cosign sign-blob \
  --wasm \
  --key cosign.key \
  --wasm-output module.signed.wasm \
  module.wasm
```

When `--wasm-output` is present, `sign-blob` treats the input as a WebAssembly
module, signs the canonical unsigned payload, and embeds the resulting bundle in
the output module. This is equivalent to the specialized `cosign wasm sign`
workflow, but the `cosign wasm` form is clearer for users and documentation.

## Verification Workflows

### Verify All Embedded Signatures with a Public Key

For a module signed with a local key pair, verify embedded bundles with the
matching public key:

```shell
cosign wasm verify \
  --key cosign.pub \
  module.signed.wasm
```

If the module contains multiple embedded `wasm-cosign` sections and no explicit
`--bundle` or `--signature` is provided, cosign verifies every embedded bundle.
Verification succeeds only if all embedded bundles verify successfully under the
provided verification options.

### Verify Keyless Signatures

For keyless signatures, specify the expected signing identity and issuer:

```shell
cosign wasm verify \
  --certificate-identity "https://github.com/example/project/.github/workflows/release.yml@refs/tags/v1.2.3" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  module.signed.wasm
```

The identity flags are evaluated for each embedded bundle. In a multi-signature
module, a single invocation should express the policy that every embedded
signature is expected to satisfy. If different signatures are expected to come
from different identities or roots of trust, extract the bundles and verify them
with separate policy invocations.

### Verify with a Trusted Root

For new-format Sigstore bundles, verification can be pinned to an explicit
TrustedRoot file:

```shell
cosign wasm verify \
  --trusted-root trusted-root.json \
  --certificate-identity "release@example.com" \
  --certificate-oidc-issuer "https://oauth2.sigstore.dev/auth" \
  module.signed.wasm
```

Use this form for controlled environments that need explicit trust material,
offline-oriented workflows, or private Sigstore deployments.

### Verify Against an External Bundle

If `--bundle` is supplied, cosign still applies the WebAssembly canonical payload
rule, but it verifies using the provided bundle instead of the embedded
`wasm-cosign` sections:

```shell
cosign wasm verify \
  --key cosign.pub \
  --bundle module.bundle.json \
  module.signed.wasm
```

This is useful when the module is unsigned, when signatures are distributed as
sidecar files, or when you want to verify one specific bundle instead of all
embedded bundles.

The same behavior is available through `verify-blob`:

```shell
cosign verify-blob \
  --wasm \
  --key cosign.pub \
  --bundle module.bundle.json \
  module.signed.wasm
```

### Verify an Unsigned Payload Produced by Stripping

The unsigned payload produced by `strip-signatures` is the same canonical byte
sequence used for signing and verification:

```shell
cosign wasm strip-signatures \
  -o module.unsigned.wasm \
  module.signed.wasm

cosign verify-blob \
  --key cosign.pub \
  --bundle module.bundle.json \
  module.unsigned.wasm
```

This can be useful for debugging or for systems that already understand
sidecar-bundle blob verification but do not yet consume embedded WebAssembly
signature sections.

## Listing Signatures

Use `list-signatures` to inspect embedded signature sections without verifying
them:

```shell
cosign wasm list-signatures module.signed.wasm
```

Text output includes:

| Field | Meaning |
| --- | --- |
| `INDEX` | Zero-based index among embedded `wasm-cosign` sections in file order. |
| `OFFSET` | Byte offset where the full custom section starts in the module. |
| `SECTION SIZE` | WebAssembly section payload size, including the custom section name and embedded payload. |
| `PAYLOAD SIZE` | Size of the embedded Sigstore bundle payload in bytes. |
| `SHA256` | SHA-256 digest of the embedded bundle payload, not of the WebAssembly module. |

For machine-readable output:

```shell
cosign wasm list-signatures \
  --output json \
  module.signed.wasm
```

Example JSON shape:

```json
[
  {
    "index": 0,
    "offset": 128344,
    "sectionSize": 24391,
    "payloadSize": 24378,
    "sha256": "4f8f9d1d9a8d6a0cf7f9e4a6c184e23f8b6c859e5f2e06d8e8e8d6c75c4d4d2a"
  },
  {
    "index": 1,
    "offset": 152738,
    "sectionSize": 24106,
    "payloadSize": 24093,
    "sha256": "6c8b55cb7f0b02b51bbda13fa8e4e22f2e9dfdceba6bfa6248a54c62f61cf2aa"
  }
]
```

The JSON fields are metadata about the embedded custom sections. They are useful
for inventory, duplicate detection, auditing, and selecting bundles to extract
for separate verification policies.

## Extracting Signatures

Use `extract-signatures` to emit the raw embedded bundle payloads:

```shell
cosign wasm extract-signatures module.signed.wasm > module.bundles.json
```

If the module contains multiple embedded signatures, payloads are emitted in
section order with a newline between payloads. For automated workflows that need
to address individual signatures, first run `list-signatures --output json` to
determine how many embedded sections are present and to record their payload
digests.

Extracted bundle payloads are verification material. They are not the unsigned
WebAssembly module. To obtain the unsigned module bytes, use
`strip-signatures`.

## Stripping Signatures

Use `strip-signatures` to remove all embedded `wasm-cosign` sections:

```shell
cosign wasm strip-signatures \
  -o module.unsigned.wasm \
  module.signed.wasm
```

The output module preserves every non-signature byte exactly. This includes all
standard WebAssembly sections and all custom sections whose name is not
`wasm-cosign`.

To use standard input and standard output:

```shell
cosign wasm strip-signatures \
  -o - \
  - < module.signed.wasm > module.unsigned.wasm
```

The stripped module is the canonical payload that cosign signs and verifies.
Removing signatures does not rewrite, optimize, normalize, or otherwise mutate
the protected module bytes.

## End-to-End Multi-Vendor Example

The following example signs a module twice and verifies that both embedded
signatures are valid.

First signer:

```shell
cosign wasm sign \
  --key vendor-a.key \
  --wasm-output module.vendor-a.wasm \
  module.wasm
```

Second signer:

```shell
cosign wasm sign \
  --key vendor-b.key \
  --wasm-output module.vendor-a-b.wasm \
  module.vendor-a.wasm
```

Inspect the embedded sections:

```shell
cosign wasm list-signatures \
  --output json \
  module.vendor-a-b.wasm
```

Verify all embedded signatures with one policy:

```shell
cosign wasm verify \
  --key shared-release.pub \
  module.vendor-a-b.wasm
```

If the two signatures require different trust policies, extract or archive each
bundle separately and verify each bundle with the appropriate identity, key, or
trusted root policy.

## Bundle Format Requirements

Embedded WebAssembly signatures use Sigstore bundles as the custom section
payload. The WebAssembly commands require the new bundle format when writing an
embedded signed module through `--wasm-output`.

The `--new-bundle-format` flag defaults to true in current cosign behavior and
is deprecated because it will be the only supported format in future versions.
The important operational point is that embedded signatures are expected to
carry the complete verification material needed by modern Sigstore verification
flows.

When verifying embedded bundles, cosign requires new-format bundle verification.
If no embedded bundle is present, provide `--bundle` or `--signature` explicitly
for sidecar verification.

## Trust and Policy Model

An embedded signature proves that a particular signer, key, certificate, or
identity signed the canonical WebAssembly module payload. It does not by itself
answer every deployment policy question.

Consumers should decide:

- Which keys, certificates, identities, or issuers are trusted.
- Whether every embedded signature must pass one shared policy.
- Whether different signature indexes represent different required roles.
- Whether a minimum number of valid signatures is required.
- Whether transparency log inclusion is mandatory.
- Whether signed timestamps are required.
- Whether the module must be stripped before storage or execution.

Cosign provides the cryptographic verification mechanism and the CLI primitives
to list, extract, strip, and verify signatures. Higher-level release gates can
compose these primitives into organization-specific policies.

## Security Considerations

Treat WebAssembly module signing with the same care as other code signing
systems:

- Protect private keys and KMS access. A valid embedded signature is only as
  strong as the controls around the signing identity.
- Prefer transparency log verification for public artifacts. Avoid
  `--insecure-ignore-tlog` unless the artifact is intentionally signed in a
  private or offline workflow.
- Pin expected identities for keyless verification with
  `--certificate-identity` or `--certificate-identity-regexp` and
  `--certificate-oidc-issuer` or `--certificate-oidc-issuer-regexp`.
- Use `--trusted-root` when verification must be tied to explicit trust
  material.
- Remember that custom sections are ignored by runtimes. A runtime executing a
  module does not automatically enforce signature verification; verification
  must be performed by the loader, package manager, deployment system, or
  policy gate.
- Do not treat `list-signatures` or `extract-signatures` as verification. They
  are inspection and extraction tools only.
- Any mutation to protected bytes invalidates existing signatures. Rebuild,
  optimize, strip non-signature sections, or post-process the module before
  signing, not after signing.

## Operational Notes

### Input Validation

The WebAssembly helper validates the module header before signing, verifying,
listing, extracting, or stripping embedded signatures. The module must start
with the WebAssembly magic header and use the supported version bytes.

If the input is not a valid WebAssembly module, the command fails instead of
treating it as an arbitrary blob.

### Section Ordering

The signing command appends a new `wasm-cosign` custom section to the end of the
module. It does not attempt to move existing signatures or normalize section
ordering.

The stripping and verification logic scans the whole module and removes every
`wasm-cosign` custom section it finds. This means it supports modules that
already contain signature sections at different valid custom-section positions.

### Other Custom Sections

Only `wasm-cosign` sections are excluded from the signed payload. Other custom
sections remain protected by the signature. This is important because custom
sections may contain meaningful debugging, provenance, producer, or toolchain
metadata. If that metadata changes after signing, verification should fail.

### In-Place Updates

The CLI writes signed and stripped modules to explicit output paths. It does not
rewrite the input file in place. This makes signing and stripping easier to use
in reproducible build pipelines where every step has a named input and output.

### Binary Output

`--wasm-output -` and `strip-signatures -o -` write raw WebAssembly bytes to
standard output. Redirect them to a file or pipe them only into binary-safe
tools.

## Troubleshooting

### `wasm module does not contain a "wasm-cosign" custom section`

The module has no embedded cosign signature sections and no explicit `--bundle`
or `--signature` was provided. Sign the module with `cosign wasm sign`, or verify
with a sidecar bundle:

```shell
cosign wasm verify \
  --key cosign.pub \
  --bundle module.bundle.json \
  module.wasm
```

### Verification Fails After Rebuilding or Optimizing

The signature covers all non-`wasm-cosign` bytes. If a tool rewrites code,
renumbers sections, changes producers metadata, strips a non-signature custom
section, or otherwise changes protected bytes, existing signatures no longer
match. Run those transformations before signing.

### Multiple Embedded Sections Are Present

When no explicit `--bundle` or `--signature` is supplied, cosign verifies all
embedded `wasm-cosign` sections. If any embedded bundle does not satisfy the
provided trust policy, verification fails. Use `list-signatures --output json`
to inspect the embedded sections and `extract-signatures` if separate policy
handling is required.

### Keyless Verification Requires Identity Flags

For keyless signatures, provide the expected certificate identity and OIDC
issuer, or their regexp variants. This prevents accepting a valid Sigstore
certificate from an unexpected identity.

### `unsupported WebAssembly version`

The input has the WebAssembly magic header but does not use the supported
version bytes. Confirm that the file is a standard `.wasm` module and not a
component, archive, compressed file, or wrapper format.

## Recommended Release Pattern

A robust release pipeline usually follows this order:

1. Build the WebAssembly module.
2. Run optimization, metadata generation, and policy checks.
3. Sign the final module with `cosign wasm sign`.
4. Optionally append additional signatures for independent approvals.
5. Verify all required signatures before publishing.
6. Publish the signed module and, if desired, archive sidecar bundles.

Avoid modifying protected module bytes after step 3. If the module must change,
produce a new signed module rather than carrying forward old signatures.
