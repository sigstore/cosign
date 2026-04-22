# Enterprise Private Infrastructure

This guide shows how to use `cosign` in a private deployment that uses:

- an internal OIDC issuer
- an internal CA or other bring-your-own PKI chain
- an RFC3161 timestamp authority
- no Rekor dependency

This model is useful when your trust and audit boundaries are private, and you want to verify signatures against internal trust roots instead of the public-good Sigstore services.

## Recommended trust model

For modern private deployments, prefer:

- `cosign signing-config create` to define the service URLs used during signing
- `cosign trusted-root create` to define the trust material used during verification
- `--private-infrastructure` during verification when signatures are not uploaded to a public transparency log

Avoid treating `--tlog-upload=false` as the long-term configuration mechanism by itself. It is better to make the "no Rekor" choice explicit in your `signing-config`.

## 1. Create a trusted root

Create a trusted root that contains your internal certificate authority chain and your TSA certificate chain.

```shell
cosign trusted-root create \
  --fulcio="url=https://ca.internal.example.com,certificate-chain=/path/to/codesigning-chain.pem" \
  --tsa="url=https://tsa.internal.example.com/api/v1/timestamp,certificate-chain=/path/to/tsa-chain.pem" \
  --out trusted-root.json
```

Notes:

- The `--fulcio` field here models the certificate authority used for signing certificates. In a private deployment, this can represent your internal CA-backed certificate issuance path.
- The `certificate-chain` should include the intermediate certificates needed for validation and end with the root certificate.

## 2. Create a signing config

Create a signing config that points signing to your internal services and omits Rekor.

```shell
cosign signing-config create \
  --fulcio="url=https://ca.internal.example.com,api-version=1,start-time=2026-01-01T00:00:00Z,operator=internal-pki" \
  --oidc-provider="url=https://oidc.internal.example.com,api-version=1,start-time=2026-01-01T00:00:00Z,operator=internal-identity" \
  --tsa="url=https://tsa.internal.example.com/api/v1/timestamp,api-version=1,start-time=2026-01-01T00:00:00Z,operator=internal-pki" \
  --tsa-config="EXACT:1" \
  --out signing-config.json
```

## 3. Sign with an internal certificate chain and TSA

If your signing flow already has a key and a short-lived signing certificate, use them directly and timestamp the signature with your TSA.

```shell
cosign sign \
  --key /path/to/codesigning.key \
  --certificate /path/to/codesigning.crt \
  --certificate-chain /path/to/codesigning-chain.pem \
  --signing-config /path/to/signing-config.json \
  --timestamp-server-url https://tsa.internal.example.com/api/v1/timestamp \
  --timestamp-client-cacert /path/to/tsa-client-ca.pem \
  --timestamp-client-cert /path/to/tsa-client.crt \
  --timestamp-client-key /path/to/tsa-client.key \
  --timestamp-server-name tsa.internal.example.com \
  $IMAGE_DIGEST
```

If your private keyless flow mints an identity token outside of `cosign`, you can also pass it with `--identity-token`, or expose it through one of the ambient providers such as `filesystem`, `envvar`, or `spiffe`.

## 4. Verify against your private trusted root

Verify using the expected signer identity and your private trusted root.

```shell
cosign verify \
  --certificate-identity "spiffe://example.internal/sa/build-job" \
  --certificate-oidc-issuer "https://oidc.internal.example.com" \
  --trusted-root /path/to/trusted-root.json \
  --private-infrastructure \
  $IMAGE_DIGEST
```

## Which trust input should I use?

- Use `--trusted-root` when you want a single modern trust bundle that covers your private CA and TSA.
- Use `--certificate-chain` when attaching or verifying the certificate chain embedded with a signature.
- Use `--ca-roots` and `--ca-intermediates` when verification inputs are managed as separate PEM bundles instead of a Sigstore trusted root.

## Air-gapped private verification

In an air-gapped environment, move the image, signatures, and your private `trusted-root.json` into the disconnected network and verify locally:

```shell
cosign save $IMAGE_DIGEST --dir ./image-dir
cosign verify \
  --certificate-identity "spiffe://example.internal/sa/build-job" \
  --certificate-oidc-issuer "https://oidc.internal.example.com" \
  --trusted-root /path/to/trusted-root.json \
  --private-infrastructure \
  --local-image ./image-dir
```
