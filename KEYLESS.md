# Keyless Signatures

The full design document for this can be found [here](https://docs.google.com/document/d/1461lQUoVqbhCve7PuKNf-2_NfpjrzBG5tFohuMVTuK4/edit#).

This document explains how the `keyless` signatures work in `cosign`.
Try it out!

This signature mode relies on the Sigstore Public Good Instance by default, but
one can also stand up private instances of Sigstore components.

The following examples use this image:

```shell
$ IMAGE=gcr.io/dlorenc-vmtest2/demo
$ IMAGE_DIGEST=$IMAGE@sha256:97fc222cee7991b5b061d4d4afdb5f3428fcb0c9054e1690313786befa1e4e36
```

## Usage

Keyless signing:

```shell
$ cosign sign $IMAGE_DIGEST
Generating ephemeral keys...
Retrieving signed certificate...
Your browser will now be opened to:
https://accounts.google.com/o/oauth2/v2/auth?access_type=offline&client_id=&redirect_uri=http%3A%2F%2F127.0.0.1%3A5556%2Fauth%2Fgoogle%2Fcallback&response_type=code
Pushing signature to: gcr.io/dlorenc-vmtest2/demo:sha256-97fc222cee7991b5b061d4d4afdb5f3428fcb0c9054e1690313786befa1e4e36.sig
```

Keyless verifying:

```shell
$ cosign verify $IMAGE
The following checks were performed on all of these signatures:
  - The cosign claims were validated
  - The claims were present in the transparency log
  - The signatures were integrated into the transparency log when the certificate was valid
  - Any certificates were verified against the Fulcio roots.
Certificate subject:  dlorenc@google.com
{"Critical":{"Identity":{"docker-reference":""},"Image":{"Docker-manifest-digest":"sha256:97fc222cee7991b5b061d4d4afdb5f3428fcb0c9054e1690313786befa1e4e36"},"Type":"cosign container image signature"},"Optional":null}
```

That's it! No keys!
The rest of the flags (annotations, claims, tlog, etc.) should all work the same.

## Overview

This uses ephemeral keys and certificates, which are signed automatically by the `fulcio` root CA.
Signatures are stored in the `rekor` transparency log, which automatically provides an attestation
as to when the signature was created.

Information on the `fulcio` root CA can be found in the [fulcio repository](https://github.com/sigstore/fulcio).

### Keys

The root CA keys are embedded in `cosign` today, see below for overriding these.

### OAuth Flows

Cosign supports two OAuth flows today: the standard flow and the device flow.

When there is no terminal attached (non-interactive mode), `cosign` will automatically use the device flow
where a link is printed to stdout.
This link must be opened in a browser to complete the flow.

### Identity Tokens

In automated environments, cosign also supports directly using OIDC Identity Tokens from specific issuers.
These can be supplied on the command line with the `--identity-token` flag.
The `audiences` field must contain `sigstore`.

`cosign` also has support for detecting some of these automated environments
and producing an identity token.  Currently this supports Google and GitHub.

#### On GCP

From a GCE VM, you can use the VM's service account identity to sign an image:

```shell
$ IDENTITY_TOKEN=$(gcloud auth print-identity-token --audiences=sigstore)
$ cosign sign --identity-token=$IDENTITY_TOKEN $IMAGE_DIGEST
```

From outside a GCE VM, you can impersonate a GCP IAM service account to sign an image:

```shell
$ IDENTITY_TOKEN=$(gcloud auth print-identity-token \
        --audiences=sigstore \
        --include-email \
        --impersonate-service-account my-sa@my-project.iam.gserviceaccount.com)
$ cosign sign --identity-token=$IDENTITY_TOKEN $IMAGE_DIGEST
```

In order to impersonate an IAM service account, your account must have the
`roles/iam.serviceAccountTokenCreator` role.

**Note**: On Google Cloud Build, standard identity tokens are not supported through the GCE metadata server.
`cosign` has a special flow for this case, where you can instruct the Cloud Build service account to impersonate
another service account.
To configure this flow:

1. Create a service account to use for signatures (the email address will be present in the certificate subject).
2. Grant the Cloud Build service account the `roles/iam.serviceAccountTokenCreator` role for this target account.
3. Set the `GOOGLE_SERVICE_ACCOUNT_NAME` environment variable to the name of the target account in your cloudbuild.yaml
4. Sign images in GCB, without keys!

### Timestamps

Signature timestamps are checked in the [rekor](https://github.com/sigstore/rekor) transparency log. Rekor's `IntegratedTime` is signed as part of its `signedEntryTimestamp`. Cosign verifies the signature over the timestamp and checks that the signature was created while the certificate was valid.

## Upcoming work

* Root CA hardening: We should use intermediate certs rather than the root, and support chained verification.
* Other timestamps: We should allow for other timestamp attestations, including attached [RFC3161](https://www.ietf.org/rfc/rfc3161.txt) signatures.
* Probably a lot more: This is very experimental.
* More OIDC providers: Obvious.

## Public Staging Environment

There is a public staging environment that is running Fulcio, Rekor and OIDC issuer.

**NOTE** The staging environment provides no SLO guarantees nor the same protection of the root key material for TUF. This environment is meant for development and testing only, PLEASE do not use for production purposes.

The endpoints are as follows:

* https://fulcio.sigstage.dev
* https://rekor.sigstage.dev
* https://oauth2.sigstage.dev/auth

These instances are operated and maintained in the same manner as the public production environment for Sigstore.

### Usage

To use this instance, follow the steps below:

1. `rm -r ~/.sigstore`
1. `gsutil cp -r gs://tuf-root-staging/root.json .`
1. `cd tuf-root-staging`
1. `cosign initialize --mirror=tuf-root-staging --root=root.json`
1. `cosign sign --oidc-issuer "https://oauth2.sigstage.dev/auth" --fulcio-url "https://fulcio.sigstage.dev" --rekor-url "https://rekor.sigstage.dev" ${IMAGE_DIGEST}`
1. `cosign verify --rekor-url "https://rekor.sigstage.dev" ${IMAGE}`

* Steps 1-4 configures your local environment to use the staging keys and certificates.
* Step 5 specify the staging environment with flags needed for signing.
* Step 6 specify the staging environment with flags needed for verifying.

#### Revert back to Production

We need to clear the local TUF root data and re-initialize with the default production TUF root data.

1. `rm -r ~/.sigstore`
1. `cosign initialize`

## Custom Infrastructure

If you're running your own sigstore services flags are available to set your own endpoint's, e.g

```
 cosign sign -oidc-issuer "https://oauth2.example.com/auth" \
                        -fulcio-url "https://fulcio.example.com" \
                        -rekor-url "https://rekor.example.com"  \
                        $IMAGE_DIGEST

```

### Custom root Cert

You can override the public good instance root CA using the environment variable `SIGSTORE_ROOT_FILE`, e.g.

```
export SIGSTORE_ROOT_FILE="/home/jdoe/myrootCA.pem"
```
