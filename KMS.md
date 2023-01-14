# KMS Integrations

This page contains detailed instructions on how to configure `cosign` to work with KMS providers.
Right now `cosign` supports Hashicorp Vault, AWS KMS, and GCP KMS, and we are hoping to support more in the future!

## Basic Usage

When referring to a key managed by a KMS provider, `cosign` takes a [go-cloud](https://gocloud.dev) style URI to refer to the specific provider.
For example:

`gcpkms://`, `awskms://`, or `hashivault://`

The URI path syntax is provider specific and explained in the section for each provider.

### Key Generation and Management

To generate keys using a KMS provider, you can use the `cosign generate-key-pair` command with the `--kms` flag.
For example:

```shell
$ cosign generate-key-pair --kms <some provider>://<some key>
```

The public key can be retrieved with:

```shell
$ cosign public-key --key <some provider>://<some key>
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXc+DQU8Pb7Xo2RWCjFG/f6qbdABN
jnVtSyKZxNzBfNMLLtVxdu8q+AigrGCS2KPmejda9bICTcHQCRUrD5OLGQ==
-----END PUBLIC KEY-----
```

### Signing and Verification

For the following examples, we have:

```shell
$ IMAGE=gcr.io/dlorenc-vmtest2/demo
$ IMAGE_DIGEST=$IMAGE@sha256:410a07f17151ffffb513f942a01748dfdb921de915ea6427d61d60b0357c1dcd
```

To sign and verify using a key managed by a KMS provider, you can pass a provider-specific URI to the `--key` command:

```shell
$ cosign sign --key <some provider>://<some key> $IMAGE_DIGEST
Pushing signature to: gcr.io/dlorenc-vmtest2/demo:sha256-410a07f17151ffffb513f942a01748dfdb921de915ea6427d61d60b0357c1dcd.cosign

$ cosign verify --key <some provider>://<some key> $IMAGE

Verification for gcr.io/dlorenc-vmtest2/demo --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - The signatures were verified against the specified public key
  - The code-signing certificate was verified using trusted certificate authority certificates

[{"critical":{"identity":{"docker-reference":"gcr.io/dlorenc-vmtest2/demo"},"image":{"docker-manifest-digest":"sha256:410a07f17151ffffb513f942a01748dfdb921de915ea6427d61d60b0357c1dcd"},"type":"cosign container image signature"},"optional":null}]
```

You can also export the public key and verify against that file:

```shell
$ cosign public-key --key <some provider>://<some key> > kms.pub
$ cosign verify --key kms.pub $IMAGE
```

### Providers

This section contains the provider-specific documentation.


### AWS

AWS KMS keys can be used in `cosign` for signing and verification.
The URI format for AWS KMS is:

`awskms://$ENDPOINT/$KEYID`

where ENDPOINT and KEYID are replaced with the correct values.

The ENDPOINT value is left blank in most scenerios, but can be set for testing with KMS-compatible servers such as [localstack](https://localstack.cloud/).
If omitting a custom endpoint, it is mandatory to prefix the URI with `awskms:///` (with three slashes).

If a custom endpoint is used, you may disable TLS verification by setting an environment variable: `AWS_TLS_INSECURE_SKIP_VERIFY=1`.

AWS credentials are provided using standard configuration as [described in AWS docs](https://docs.aws.amazon.com/sdk-for-go/v1/developer-guide/configuring-sdk.html#specifying-credentials).

The KEYID value must conform to any [AWS KMS key identifier](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#key-id)
format as described in the linked document (Key ARN, Key ID, Alias ARN, or Alias ID).

Note that key creation is not supported by cosign if using the Key ARN or Key ID formats, so it is recommended to use [Key Aliases](https://docs.aws.amazon.com/kms/latest/developerguide/kms-alias.html)
for most situations.

The following URIs are valid:

- Key ID: `awskms:///1234abcd-12ab-34cd-56ef-1234567890ab`
- Key ID with endpoint: `awskms://localhost:4566/1234abcd-12ab-34cd-56ef-1234567890ab`
- Key ARN: `awskms:///arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab`
- Key ARN with endpoint: `awskms://localhost:4566/arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab`
- Alias name: `awskms:///alias/ExampleAlias`
- Alias name with endpoint: `awskms://localhost:4566/alias/ExampleAlias`
- Alias ARN: `awskms:///arn:aws:kms:us-east-2:111122223333:alias/ExampleAlias`
- Alias ARN with endpoint: `awskms://localhost:4566/arn:aws:kms:us-east-2:111122223333:alias/ExampleAlias`

Example:

```shell
$ export AWS_REGION=us-east-1
$ export AWS_CMK_ID=$(aws kms create-key --customer-master-key-spec RSA_4096 \
                                         --key-usage SIGN_VERIFY \
                                         --description "Cosign Signature Key Pair" \
                                         --query KeyMetadata.KeyId --output text)

$ cosign sign --key awskms:///${AWS_CMK_ID} $IMAGE_DIGEST
$ cosign verify --key awskms:///${AWS_CMK_ID} $IMAGE | jq .
```

### GCP

GCP KMS keys can be used in `cosign` for signing and verification.
The URI format for GCP KMS is:

`gcpkms://projects/$PROJECT/locations/$LOCATION/keyRings/$KEYRING/cryptoKeys/$KEY/versions/$KEY_VERSION`

where PROJECT, LOCATION, KEYRING, KEY and KEY_VERSION are replaced with the correct values.

Cosign automatically uses GCP Application Default Credentials for authentication.
See the GCP [API documentation](https://cloud.google.com/docs/authentication/production) for information on how to authenticate in different environments.

The user must have the following IAM roles:
* Safer KMS Viewer Role
* Cloud KMS CryptoKey Signer/Verifier (`roles/cloudkms.signerVerifier`)

### Azure Key Vault

Azure Key Vault keys can be used in `cosign` for signing and verification.

The URI format for Azure Key Vault is:
`azurekms://[VAULT_NAME][VAULT_URI]/[KEY]`

where VAULT_NAME, VAULT_URI, and KEY are replaced with the correct values.

The following environment variables must be set to let cosign authenticate to Azure Key Vault. (see this [reference](https://devblogs.microsoft.com/azure-sdk/authentication-and-the-azure-sdk/#environment-variables) for more details about Azure SDK Authentication)
- AZURE_TENANT_ID
- AZURE_CLIENT_ID
- AZURE_CLIENT_SECRET

To create a key using `cosign generate-key-pair --kms azurekms://[VAULT_NAME][VAULT_URI]/[KEY]` you will need a user which has permissions to create keys in Key Vault. For example `Key Vault Crypto Officer` role.

To sign images using `cosign sign --key azurekms://[VAULT_NAME][VAULT_URI]/[KEY] [IMAGE DIGEST]` you will need a user which has permissions to the sign action such as the `Key Vault Crypto User` role.

### Hashicorp Vault

Hashicorp Vault keys can be used in `cosign` for signing and verification.
The URI format for Hashicorp Vault KMS is:

`hashivault://$keyname`

This provider requires that the standard Vault environment variables (VAULT_ADDR, VAULT_TOKEN) are set correctly.
This provider also requires that the `transit` secret engine is enabled

### Kubernetes Secret

Cosign can use keys stored in Kubernetes Secrets to so sign and verify signatures. In
order to generate a secret you have to pass `cosign generate-key-pair` a
`k8s://[NAMESPACE]/[NAME]` URI specifying the namespace and secret name:

```
cosign generate-key-pair k8s://default/testsecret
Enter password for private key: ****
Enter again: ****
Successfully created secret testsecret in namespace default
Public key written to cosign.pub
```

After generating the key pair, cosign will store it in a Kubernetes secret using
your current context. The secret will contain the private and public keys, as 
well as the password to decrypt the private key.

The secret has the following structure:

```
apiVersion: v1
kind: Secret
metadata:
  name: testsecret
  namespace: default
type: Opaque
data:
  cosign.key: LS0tLS1CRUdJTiBFTkNSWVBURUQgQ09TSUdOIFBSSVZBVEUgS0VZLS0tLS[...]==
  cosign.password: YWJjMTIz
  cosign.pub: LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQo[...]==
```

When verifying an image signature using `cosign verify`, the key will be automatically
decrypted using the password stored in the kubernetes secret under the `cosign.password`
field.

#### Local Setup

For a local setup, you can run Vault yourself or use the `docker-compose` file from [sigstore/sigstore](https://github.com/sigstore/sigstore/blob/main/test/e2e/docker-compose.yml) as an example.

After running it:

```shell
$ export VAULT_ADDR=http://localhost:8200
$ export VAULT_TOKEN=testtoken
$ vault secrets enable transit
```

If you enabled `transit` secret engine at different path with the use of `-path` flag (i.e., `$ vault secrets enable -path="someotherpath" transit`), you can use `TRANSIT_SECRET_ENGINE_PATH` environment variable to specify this path while generating a key pair like the following:

```shell
$ TRANSIT_SECRET_ENGINE_PATH="someotherpath" cosign generate-key-pair --kms hashivault://testkey
```
