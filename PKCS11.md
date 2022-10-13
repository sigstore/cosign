# PKCS11 Tokens

The `cosign` command line tool optionally supports PKCS11 tokens for signing.
This support is enabled through the [crypto11](https://github.com/ThalesIgnite/crypto11) and the [pkcs11](https://github.com/miekg/pkcs11) libraries, which are not included in the standard release. Use [`make cosign-pivkey-pkcs11key`](https://github.com/sigstore/cosign/blob/a8d1cc1132d4a019a62ff515b9375c8c5b98a5c5/Makefile#L52), or `go build -tags=pkcs11key`, to build `cosign` with support for PKCS11 tokens.

For the following examples, we have:

```shell
$ IMAGE=gcr.io/dlorenc-vmtest2/demo
$ IMAGE_DIGEST=$IMAGE@sha256:410a07f17151ffffb513f942a01748dfdb921de915ea6427d61d60b0357c1dcd
```

## Quick Start

### Setup

To get started, make sure you already have your PKCS11 module installed, and insert your PKCS11-compatible token.

Then, run the command `cosign pkcs11-tool list-tokens` to get the slot id of your token, as follows :

```shell
$ cosign pkcs11-tool list-tokens --module-path /usr/local/lib/libp11.so
Listing tokens of PKCS11 module '/usr/local/lib/libp11.so'
Token in slot 1
        Label: TokenLabel
        Manufacturer: Token Manufacturer
        Model: Token Model
        S/N: 68800ca5c75e074c
```

Afterwards, run the command `cosign pkcs11-tool list-keys-uris` to retrieve the PKCS11 URI of the key you wish to use, as follows :

```shell
$ cosign pkcs11-tool list-keys-uris --module-path /usr/local/lib/libp11.so --slot-id 1 --pin 1234
Listing URIs of keys in slot '1' of PKCS11 module '/usr/local/lib/libp11.so'
Object 0
        Label: key_label_1
        ID: 4a8d2f6ed9c4152b260d6c74a1ae72fcfdc64b65
        URI: pkcs11:token=TokenLabel;slot-id=1;id=%4a%8d%2f%6e%d9%c4%15%2b%26%0d%6c%74%a1%ae%72%fc%fd%c6%4b%65?module-path=/usr/local/lib/libp11.so&pin-value=1234
Object 1
        Label: key_label_2
        ID: 57b39235cc6dec404c2310d7e37d5cbb5f1bba70
        URI: pkcs11:token=TokenLabel;slot-id=1;id=%57%b3%92%35%cc%6d%ec%40%4c%23%10%d7%e3%7d%5c%bb%5f%1b%ba%70?module-path=/usr/local/lib/libp11.so&pin-value=1234
```

You can also construct the PKCS11 URI of your key manually by providing the following URI components :

* **module-path** : the absolute path to the PKCS11 module **(optional)**

* **token** and/or **slot-id** : either or both of the PKCS11 token label and the PKCS11 slot id **(mandatory)**

* **object** and/or **id** : either or both of the PKCS11 key label and the PKCS11 key id **(mandatory)**

* **pin-value** : the PIN of the PKCS11 token **(optional)**

If `module-path` is not present in the URI, `cosign` expects the PKCS11 module path to be set using the environment variable `COSIGN_PKCS11_MODULE_PATH`. If neither are set, `cosign` will fail. If both are set, `module-path` has priority over `COSIGN_PKCS11_MODULE_PATH` environment variable.

If `pin-value` is not present in the URI, `cosign` expects the PIN to be set using the environment variable `COSIGN_PKCS11_PIN`. If it is not, `cosign` checks whether the PKCS11 token requires user login (flag CKF_LOGIN_REQUIRED set), and if so, `cosign` will invite the user to enter the PIN only during signing. If both `pin-value` and `COSIGN_PKCS11_PIN` environment variable are set, `pin-value` has priority over `COSIGN_PKCS11_PIN`.

### Signing

You can then use the normal `cosign` commands to sign images and blobs with your PKCS11 key.

```shell
$ cosign sign --key "<PKCS11_URI>" $IMAGE_DIGEST
Pushing signature to: gcr.io/dlorenc-vmtest2/demo:sha256-410a07f17151ffffb513f942a01748dfdb921de915ea6427d61d60b0357c1dcd.sig
```

To verify, you can either use the PKCS11 token key directly:

```shell
$ cosign verify --key "<PKCS11_URI>" $IMAGE
Verification for gcr.io/dlorenc-vmtest2/demo --
The following checks were performed on each of these signatures:
- The cosign claims were validated
- The signatures were verified against the specified public key
- Any certificates were verified against the Fulcio roots.

[{"critical":{"identity":{"docker-reference":"gcr.io/dlorenc-vmtest2/demo"},"image":{"docker-manifest-digest":"sha256:410a07f17151ffffb513f942a01748dfdb921de915ea6427d61d60b0357c1dcd"},"type":"cosign container image signature"},"optional":null}]
```

Or export the public key and verify against that:

```shell
$ cosign public-key --key "<PKCS11_URI>" > pub.key

$ cosign verify --key pub.key $IMAGE_DIGEST
Verification for gcr.io/dlorenc-vmtest2/demo --
The following checks were performed on each of these signatures:
- The cosign claims were validated
- The signatures were verified against the specified public key
- Any certificates were verified against the Fulcio roots.

[{"critical":{"identity":{"docker-reference":"gcr.io/dlorenc-vmtest2/demo"},"image":{"docker-manifest-digest":"sha256:410a07f17151ffffb513f942a01748dfdb921de915ea6427d61d60b0357c1dcd"},"type":"cosign container image signature"},"optional":null}]

```
