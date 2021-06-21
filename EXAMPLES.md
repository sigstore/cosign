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
$ cosign download us-central1-docker.pkg.dev/dlorenc-vmtest2/test/taskrun > signatures.json
# There could be multiple signatures, let's pretend it's the last one.
# Extract the payload and signature, base64 decoding them.
$ cat signatures.json | tail -1 | jq -r .Payload | base64 -D > payload
$ cat signatures.json | tail -1 | jq -r .Base64Signature | base64 -D > signature
# Now download the public key
$ gcloud kms keys versions get-public-key 1 --key=foo --keyring=foo --location=us-central1 > pubkey.pem
# Verify in openssl
$ openssl dgst -sha256 -verify pubkey.pem -signature gcpkms.sig payload
```
