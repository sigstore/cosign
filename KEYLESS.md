# Keyless Signatures

The full design document for this can be found [here](https://docs.google.com/document/d/189w4Fp1GEA1b2P633HyqTwtcWFNTu_Af4meolMa_1_8/edit?resourcekey=0-QoqNqcHXvSuPnMUdn8RGOQ#heading=h.2mtrw7byet02)
(join sigstore-dev@googlegroups.com for access).

🚨 🚨 **ExPeRiMeNtAl** 🚨 🚨

This document explains how the experimental `keyless` signatures work in `cosign`.
Try it out!

## Usage

Keyless signing:

```shell
$ COSIGN_EXPERIMENTAL=1 cosign sign gcr.io/dlorenc-vmtest2/demo
Generating ephemeral keys...
Retrieving signed certificate...
Your browser will now be opened to:
https://accounts.google.com/o/oauth2/v2/auth?access_type=offline&client_id=237800849078-rmntmr1b2tcu20kpid66q5dbh1vdt7aj.apps.googleusercontent.com&redirect_uri=http%3A%2F%2F127.0.0.1%3A5556%2Fauth%2Fgoogle%2Fcallback&response_type=code&scope=openid+email&state=8slZXeZhwKQofg%3D%3D
Pushing signature to: gcr.io/dlorenc-vmtest2/demo:sha256-97fc222cee7991b5b061d4d4afdb5f3428fcb0c9054e1690313786befa1e4e36.sig
```

Keyless verifying:

```shell
$ COSIGN_EXPERIMENTAL=1 cosign verify gcr.io/dlorenc-vmtest2/demo
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

The root CA keys are hard-coded in `cosign` today.
They can only be changed by recompiling the binary.
This will be made more configurable in the future.

### Oauth Flows

Cosign supports two oauth flows today: the standard flow and the device flow.

When there is no terminal attached (non-interactive mode), `cosign` will automatically use the device flow
where a link is printed to stdout.
This link must be opened in a browser to complete the flow.

### Identity Tokens

In automated environments, cosign also supports directly using OIDC Identity Tokens from specific issuers.
These can be supplied on the command line with the `--identity-token` flag.
The `audiences` field must contain `fulcio`.

One example usage is:

```shell
$ cosign sign --identity-token=$(gcloud auth print-identity-token --audiences=fulcio) gcr.io/dlorenc-vmtest2/demo
```

### Timestamps

Signature timestamps are checked in the [rekor](https://github.com/sigstore/rekor) transparency log. Rekor's `IntegratedTime` is signed as part of its `signedEntryTimestamp`. Cosign verifies the signature over the timestamp and checks that the signature was created while the certificate was valid.

## Upcoming work

* Root CA hardening: We should use intermediate certs rather than the root, and support chained verification.
* Root CA configuration: We should allow users to change the roots and add their own.
* Other timestamps: We should allow for other timestamp attestations, including attached [RFC3161](https://www.ietf.org/rfc/rfc3161.txt) signatures.
* Probably a lot more: This is very experimental.
* More OIDC providers: Obvious.

## Custom Infrastructure

If you're running your own sigtore services flags are available to set your own endpoint's, e.g

```
 COSIGN_EXPERIMENTAL=1 go run cmd/cosign/main.go sign -oidc-issuer "https://oauth2.example.com/auth" \
                        -fulcio-url "https://fulcio.example.com" \
                        -rekor-url "https://rekor.example.com"  \
                        ghcr.io/jdoe/somerepo/testcosign

```

### Custom root Cert

You can override the public good instance root CA using the enviromental variable `SIGSTORE_ROOT_DIR`, e.g.

```
export SIGSTORE_ROOT_FILE="/home/jdoe/myrootCA.pem"
```