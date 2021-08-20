# Other cosign examples

## GCP KMS with `gcloud`

Use `cosign` to generate the payload, sign it with `gcloud kms`, then use `cosign` to upload it.

```shell
$ cosign generate us-central1-docker.pkg.dev/dlorenc-vmtest2/test/taskrun > payload.json
$ gcloud kms asymmetric-sign --digest-algorithm=sha256 --input-file=payload.json --signature-file=gcpkms.sig --key=foo --keyring=foo --version=1 --location=us-central
# We have to base64 encode the signature
$ cat gcpkms.sig | base64 | cosign attach signature -signature - us-central1-docker.pkg.dev/dlorenc-vmtest2/test/taskrun
```

Now (on another machine) download the public key, payload, signatures and verify it!

```shell
$ cosign download signature us-central1-docker.pkg.dev/dlorenc-vmtest2/test/taskrun > signatures.json
# There could be multiple signatures, let's pretend it's the last one.
# Extract the payload and signature, base64 decoding them.
$ cat signatures.json | tail -1 | jq -r .Payload | base64 -D > payload
$ cat signatures.json | tail -1 | jq -r .Base64Signature | base64 -D > signature
# Now download the public key
$ gcloud kms keys versions get-public-key 1 --key=foo --keyring=foo --location=us-central1 > pubkey.pem
# Verify in openssl
$ openssl dgst -sha256 -verify pubkey.pem -signature gcpkms.sig payload
```
## Sign With OpenSSL, Verify With Cosign

```shell
# Generate a keypair
$ openssl ecparam -name prime256v1 -genkey -noout -out openssl.key
$ openssl ec -in openssl.key -pubout -out openssl.pub
# Generate the payload to be signed
$ cosign generate us.gcr.io/dlorenc-vmtest2/demo > payload.json
# Sign it and convert to base64
$ openssl dgst -sha256 -sign openssl.key -out payload.sig payload.json
$ cat payload.sig | base64 > payloadbase64.sig
# Upload the signature
$ cosign attach signature -payload payload.json -signature payloadbase64.sig  us.gcr.io/dlorenc-vmtest2/demo
# Verify!
$ cosign verify -key openssl.pub us.gcr.io/dlorenc-vmtest2/demo
Verification for us.gcr.io/dlorenc-vmtest2/demo --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - The signatures were verified against the specified public key
  - Any certificates were verified against the Fulcio roots.
{"critical":{"identity":{"docker-reference":"us.gcr.io/dlorenc-vmtest2/demo"},"image":{"docker-manifest-digest":"sha256:124e1fdee94fe5c5f902bc94da2d6e2fea243934c74e76c2368acdc8d3ac7155"},"type":"cosign container image signature"},"optional":null}
```