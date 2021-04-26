# KMS Integrations

This page contains detailed instructions on how to configure `cosign` to work with KMS providers.
Right now `cosign` supports Vault and GCP KMS, but are hoping to support more in the future!

## Basic Usage

When referring to a key managed by a KMS provider, `cosign` takes a [go-cloud](https://gocloud.dev) style URI to refer to the specific provider.
For example:

`gcpkms://` or `hashivault://`

The URI path sytnax is provider specific and explained in the section for each provider.

### Key Generation and Management

To generate keys using a KMS provider, you can use the `cosign generate-key-pair` command with the `-kms` flag.
For example:

```shell
$ cosign generate-key-pair -kms <some provider>://<some key>
```

The public key can be retrieved with:

```shell
$ cosign public-key -key <some provider>://<some key>
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXc+DQU8Pb7Xo2RWCjFG/f6qbdABN
jnVtSyKZxNzBfNMLLtVxdu8q+AigrGCS2KPmejda9bICTcHQCRUrD5OLGQ==
-----END PUBLIC KEY-----
```

### Signing and Verification

To sign and verify using a key managed by a KMS provider, you can pass a provider-specific URI to the `-key` command:

```shell
$ cosign sign -key <some provider>://<some key> gcr.io/dlorenc-vmtest2/demo
Pushing signature to: gcr.io/dlorenc-vmtest2/demo:sha256-410a07f17151ffffb513f942a01748dfdb921de915ea6427d61d60b0357c1dcd.cosign

$ cosign verify -key <some provider>://<some key> gcr.io/dlorenc-vmtest2/demo

Verification for gcr.io/dlorenc-vmtest2/demo --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - The signatures were verified against the specified public key
  - Any certificates were verified against the Fulcio roots.

[{"critical":{"identity":{"docker-reference":"gcr.io/dlorenc-vmtest2/demo"},"image":{"docker-manifest-digest":"sha256:410a07f17151ffffb513f942a01748dfdb921de915ea6427d61d60b0357c1dcd"},"type":"cosign container image signature"},"optional":null}]
```

You can also export the public key and verify against that file:

```shell
$ cosign public-key -key <some provider>://<some key> > kms.pub
$ cosign verify -key kms.pub gcr.io/dlorenc-vmtest2/demo
```

### Providers

This section contains the provider-specific documentation.

### GCP

GCP KMS keys can be used in `cosign` for signing and verification.
The URI format for GCP KMS is:

`gcpkms://projects/$PROJECT/locations/$LOCATION/keyRings/$KEYRING/cryptoKeys/$KEY`

where PROJECT, LOCATION, KEYRUNG and KEY are replaced with the correct values.

Cosign automatically uses GCP Application Default Credentials for authentication.
See the GCP [API documentation](https://cloud.google.com/docs/authentication/production) for information on how to authenticate in different environments.

The user must have the following IAM roles:
* Safer KMS Viewer Role
* Cloud KMS CryptoKey Signer/Verifier

### Hashicorp Vault

Hashicorp Vault keys can be used in `cosign` for signing and verification.
The URI format for Hashicorp Vault KMS is:

`hashivault://$keyname`

This provider requires that the standard Vault environment variables (VAULT_ADDR, VAULT_TOKEN) are set correctly.
This provider also requires that the `transit` secret engine is enabled


#### Local Setup

For a local setup, you can run Vault yourself or use the `docker-compose` file from [sigstore/sigstore](https://github.com/sigstore/sigstore/blob/main/test/e2e/docker-compose.yml) as an example.

After running it:

```
$ export VAULT_ADDR=http://localhost:8200
$ export VAULT_TOKEN=testtoken
$ vault secrets enable transit
```
