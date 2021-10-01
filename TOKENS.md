# Hardware Tokens

The `cosign` command line tool optionally supports hardware tokens for signing and key management.
This support is enabled through the [PIV protocol](https://csrc.nist.gov/projects/piv/piv-standards-and-supporting-documentation)
and the [go-piv](https://github.com/go-piv/piv-go) library, which is not included in the standard release. Use [`make cosign-pivkey`](https://github.com/sigstore/cosign/blob/a8d1cc1132d4a019a62ff515b9375c8c5b98a5c5/Makefile#L52), or `go build -tags=pivkey`, to build `cosign` with support for hardware tokens.

---
**NOTE**

`cosign`'s hardware token support requires `libpcsclite` on platforms other than Windows and OSX.
See [`go-piv`'s installation instructions for your platform.](https://github.com/go-piv/piv-go#installation)

---

We recommend using an application provided by your hardware vendor to manage keys and permissions for advanced use-cases, but `cosign piv-tool` should work well for most users.

## Quick Start

### Setup

To get started, insert a key to your computer and run the `cosign generate-key` command.
We recommend using the `--random-management-key=true` flag.

This command generates a cryptographically-random management key and configures the device to use it.
This management key is destroyed, requiring a hardware reset to modify the signing key (this can be done with the `cosign piv-tool reset` command).

A signing key is generated on the hardware, and the resulting attestations are printed to stdout.
You do not need to save these, they can be retrieved later with the `cosign piv-tool attestation` command.

```shell
$ cosign piv-tool generate-key --random-management-key
Resetting management key to random value. You must factory reset the device to change this value: y
Generating new signing key. This will destroy any previous keys.: y
Generated public key
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEbZHvZgxjkqWlY865CPlmAqjLK6y
PhL+7MoxI3LLmO/gOhH8Q6elVcAZJgAUZY+GXlN0u1/TatI+sdw2DEQThw==
-----END PUBLIC KEY-----

Printing device attestation certificate
-----BEGIN CERTIFICATE-----
MIIC+jCCAeKgAwIBAgIJAJDjrwcvIYiiMA0GCSqGSIb3DQEBCwUAMCsxKTAnBgNV
BAMMIFl1YmljbyBQSVYgUm9vdCBDQSBTZXJpYWwgMjYzNzUxMCAXDTE2MDMxNDAw
MDAwMFoYDzIwNTIwNDE3MDAwMDAwWjAhMR8wHQYDVQQDDBZZdWJpY28gUElWIEF0
dGVzdGF0aW9uMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyS4ANsMp
RQA9cigP1oUG8yQ8tQkel2IergXvY9WSYy/muj30exFWXvO323i9RaQtoT7hOS5d
SsH1hNvSTD56fIaKpg+8jHsQLM6mF2Jo0Kb4rBduYNi+waFbGcwgrmRX1d9NcYb6
UDJt0o0RW6aGPY6wqUvMlIj0EwNIN7Ct1wSjIdL1qFmyVwUkQkPDd/0jDv7giE0P
M36qISQ6U8t2jNg5aWDEjf7wwWTIiMjbv0FaaiL5Vqmc7WboofKZN5nQyWGAtAtz
jTXzSkBfNPDO1eAUgbCbmu5efD8WeAtiPQyz8zQDU5UyihmDUEF1Dgr9/QMtQ5bd
Z+FkBTtBYFp4aQIDAQABoykwJzARBgorBgEEAYLECgMDBAMFAgYwEgYDVR0TAQH/
BAgwBgEB/wIBADANBgkqhkiG9w0BAQsFAAOCAQEAQutaY0Wf/o2MPyRmsMM1QQuX
JI1ncaiDczWpFGj8YFUqlwLsEgYMzzGMrgPHIyE+CCgbYfyJu2mGU7goEHFq2/Ky
i8mjJtk/nVMF/m+dD7zbLvXPU0f9BKdpm1LUjC/YscvkFuI+sFrZvk8e1DAM49D5
Dm3MsEw9KjGhhTSv8iMoz9QMN7O1ozfsLTkj5eJQFEzkeUtgPxoJVnJqd4JkqnhF
ZoN7tG+9N6wouG5pCzOJDgraGwow11UdcheQze2SVktYcRdWVgr86YBiYdfAzkLz
FN4tXEiGuQyX6gWKBdd91niHF27RIWNGuz6X9KzMwgJ374n2ld8BiLg9PU30xA==
-----END CERTIFICATE-----

Printing key attestation certificate
-----BEGIN CERTIFICATE-----
MIICVTCCAT2gAwIBAgIQARbGLrd6RGhDODMN+neZczANBgkqhkiG9w0BAQsFADAh
MR8wHQYDVQQDDBZZdWJpY28gUElWIEF0dGVzdGF0aW9uMCAXDTE2MDMxNDAwMDAw
MFoYDzIwNTIwNDE3MDAwMDAwWjAlMSMwIQYDVQQDDBpZdWJpS2V5IFBJViBBdHRl
c3RhdGlvbiA5YzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBG2R72YMY5KlpWP
OuQj5ZgKoyyusj4S/uzKMSNyy5jv4DoR/EOnpVXAGSYAFGWPhl5TdLtf02rSPrHc
NgxEE4ejTjBMMBEGCisGAQQBgsQKAwMEAwUCBjAUBgorBgEEAYLECgMHBAYCBADH
kP4wEAYKKwYBBAGCxAoDCAQCAwIwDwYKKwYBBAGCxAoDCQQBAzANBgkqhkiG9w0B
AQsFAAOCAQEAesDBFM7J67HCaJ6YzF2Ztz9UwQWVVid9AXG0b3rTdDBUAm85I+9a
zr8kS/adx2DKXQwQ2XTkSh4uMd4vVXMPr/MCiVzKzVnCgel1Fv97OaozpEicnTTn
0/cvf6NSdFeRDL06NBphp3gdWEkvuTb0LmCKnCldKbtGllK6yfZ/kVZexdnUrFIi
Hy45LclHKHKe3nveDD1WuGCpSABrxkx/BL/BNHB1y/gwiPHBFX+RShAtHwlW8uDK
g/8KdqKm021Eq/NJ+3WxINbRLFgYx8b+jTc7TE6ASNSNnbeG9UYlJ8kzfVII6C/4
H0RutMyJMyduyT5c8F3OmDY5FDdX1F1VRQ==
-----END CERTIFICATE-----

Verifying certificates...
Verified ok

Device info:
  Issuer: CN=Yubico PIV Root CA Serial 263751
  Form factor: unknown: 0
  PIN Policy: Always
  Serial number: 10550341
  Version: 4.4.5
```

### Signing

You can then use the normal `cosign` commands to sign images and blobs with your security key and PIN.
**NOTE**: The default PIN is `123456`.

```shell
$ cosign sign --sk gcr.io/dlorenc-vmtest2/demo
Enter PIN for security key:
Please tap security key...
Pushing signature to: gcr.io/dlorenc-vmtest2/demo:sha256-410a07f17151ffffb513f942a01748dfdb921de915ea6427d61d60b0357c1dcd.sig
```

To verify, you can either use the hardware key directly:

```shell
$ cosign verify --sk gcr.io/dlorenc-vmtest2/demo

Verification for gcr.io/dlorenc-vmtest2/demo --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - The signatures were verified against the specified public key
  - Any certificates were verified against the Fulcio roots.

[{"critical":{"identity":{"docker-reference":"gcr.io/dlorenc-vmtest2/demo"},"image":{"docker-manifest-digest":"sha256:410a07f17151ffffb513f942a01748dfdb921de915ea6427d61d60b0357c1dcd"},"type":"cosign container image signature"},"optional":null}]
```

Or export the public key and verify against that:

```shell
$ cosign public-key --sk > pub.key

$ cosign verify --key pub.key gcr.io/dlorenc-vmtest2/demo

Verification for gcr.io/dlorenc-vmtest2/demo --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - The signatures were verified against the specified public key
  - Any certificates were verified against the Fulcio roots.

[{"critical":{"identity":{"docker-reference":"gcr.io/dlorenc-vmtest2/demo"},"image":{"docker-manifest-digest":"sha256:410a07f17151ffffb513f942a01748dfdb921de915ea6427d61d60b0357c1dcd"},"type":"cosign container image signature"},"optional":null}]
```

## CLI Usage

### Setup

The `cosign piv-tool reset` command will restore your device to factory defaults.
This will **DESTROY** any keys on the device, you cannot recover them.

The default management key, PIN and PUK will be configured after this command.

The `cosign piv-tool generate-key` command is used to provision a key compatible with `cosign` and the rest of `sigstore`.
We recommend using the `--random-management-key=true` flag.

### Access Control

The management-key, PIN and PUK can all be configured with the `set-management-key`, `set-pin` and `set-puk` commands.
Leaving the `old-<type>` flag empty will result in the default value being used.

The PIN is used for signing, so you should set that to a value you can remember.
The PUK is used to reset the PIN in case you forget, without needing to regenerate the signing key.

We recommend configuring these after the initial setup and key generation.

## Tested Devices

This set of commands has been tested against the following hardware:

* YubiKey 5C
* YuibiKey 5C Nano FIPS
* YubiKey 4 Series

**Note**: We aim to expand this list.
If you have hardware and can test it out, please send a PR with your results!

Tests can be run against a device with the following command.
**WARNING**: These tests will destroy any keys on your device.

```shell
$ go test ./test -tags=resetyubikey,e2e -count=1
```

**WARNING**: These tests will destroy any keys on your device.

## Attestations

There are two attestations available from the hardware key.
The first is the device attestation.
This can be used to verify the hardware is authentic and came from the manufacturer.
To verify this, retrieve the manufacturers CA.
See [here](https://developers.yubico.com/yubico-piv-tool/Attestation.html) for instructions from Yubico.

This certificate can be validated with `openssl` or other tooling:

```shell
# Obtained from https://developers.yubico.com/PIV/Introduction/piv-attestation-ca.pem
$ echo '-----BEGIN CERTIFICATE-----
MIIDFzCCAf+gAwIBAgIDBAZHMA0GCSqGSIb3DQEBCwUAMCsxKTAnBgNVBAMMIFl1
YmljbyBQSVYgUm9vdCBDQSBTZXJpYWwgMjYzNzUxMCAXDTE2MDMxNDAwMDAwMFoY
DzIwNTIwNDE3MDAwMDAwWjArMSkwJwYDVQQDDCBZdWJpY28gUElWIFJvb3QgQ0Eg
U2VyaWFsIDI2Mzc1MTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMN2
cMTNR6YCdcTFRxuPy31PabRn5m6pJ+nSE0HRWpoaM8fc8wHC+Tmb98jmNvhWNE2E
ilU85uYKfEFP9d6Q2GmytqBnxZsAa3KqZiCCx2LwQ4iYEOb1llgotVr/whEpdVOq
joU0P5e1j1y7OfwOvky/+AXIN/9Xp0VFlYRk2tQ9GcdYKDmqU+db9iKwpAzid4oH
BVLIhmD3pvkWaRA2H3DA9t7H/HNq5v3OiO1jyLZeKqZoMbPObrxqDg+9fOdShzgf
wCqgT3XVmTeiwvBSTctyi9mHQfYd2DwkaqxRnLbNVyK9zl+DzjSGp9IhVPiVtGet
X02dxhQnGS7K6BO0Qe8CAwEAAaNCMEAwHQYDVR0OBBYEFMpfyvLEojGc6SJf8ez0
1d8Cv4O/MA8GA1UdEwQIMAYBAf8CAQEwDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3
DQEBCwUAA4IBAQBc7Ih8Bc1fkC+FyN1fhjWioBCMr3vjneh7MLbA6kSoyWF70N3s
XhbXvT4eRh0hvxqvMZNjPU/VlRn6gLVtoEikDLrYFXN6Hh6Wmyy1GTnspnOvMvz2
lLKuym9KYdYLDgnj3BeAvzIhVzzYSeU77/Cupofj093OuAswW0jYvXsGTyix6B3d
bW5yWvyS9zNXaqGaUmP3U9/b6DlHdDogMLu3VLpBB9bm5bjaKWWJYgWltCVgUbFq
Fqyi4+JE014cSgR57Jcu3dZiehB6UtAPgad9L5cNvua/IWRmm+ANy3O2LH++Pyl8
SREzU8onbBsjMg9QDiSf5oJLKvd/Ren+zGY7
-----END CERTIFICATE-----' > yubico.crt

# Obtained from "cosign piv-tool attestation" (the first certificate)
$ echo '-----BEGIN CERTIFICATE-----
MIIC+jCCAeKgAwIBAgIJAJDjrwcvIYiiMA0GCSqGSIb3DQEBCwUAMCsxKTAnBgNV
BAMMIFl1YmljbyBQSVYgUm9vdCBDQSBTZXJpYWwgMjYzNzUxMCAXDTE2MDMxNDAw
MDAwMFoYDzIwNTIwNDE3MDAwMDAwWjAhMR8wHQYDVQQDDBZZdWJpY28gUElWIEF0
dGVzdGF0aW9uMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyS4ANsMp
RQA9cigP1oUG8yQ8tQkel2IergXvY9WSYy/muj30exFWXvO323i9RaQtoT7hOS5d
SsH1hNvSTD56fIaKpg+8jHsQLM6mF2Jo0Kb4rBduYNi+waFbGcwgrmRX1d9NcYb6
UDJt0o0RW6aGPY6wqUvMlIj0EwNIN7Ct1wSjIdL1qFmyVwUkQkPDd/0jDv7giE0P
M36qISQ6U8t2jNg5aWDEjf7wwWTIiMjbv0FaaiL5Vqmc7WboofKZN5nQyWGAtAtz
jTXzSkBfNPDO1eAUgbCbmu5efD8WeAtiPQyz8zQDU5UyihmDUEF1Dgr9/QMtQ5bd
Z+FkBTtBYFp4aQIDAQABoykwJzARBgorBgEEAYLECgMDBAMFAgYwEgYDVR0TAQH/
BAgwBgEB/wIBADANBgkqhkiG9w0BAQsFAAOCAQEAQutaY0Wf/o2MPyRmsMM1QQuX
JI1ncaiDczWpFGj8YFUqlwLsEgYMzzGMrgPHIyE+CCgbYfyJu2mGU7goEHFq2/Ky
i8mjJtk/nVMF/m+dD7zbLvXPU0f9BKdpm1LUjC/YscvkFuI+sFrZvk8e1DAM49D5
Dm3MsEw9KjGhhTSv8iMoz9QMN7O1ozfsLTkj5eJQFEzkeUtgPxoJVnJqd4JkqnhF
ZoN7tG+9N6wouG5pCzOJDgraGwow11UdcheQze2SVktYcRdWVgr86YBiYdfAzkLz
FN4tXEiGuQyX6gWKBdd91niHF27RIWNGuz6X9KzMwgJ374n2ld8BiLg9PU30xA==
-----END CERTIFICATE-----' > device.crt

$ openssl verify -CAfile yubico.crt device.crt
device.crt: OK
```

The key attestation can be used to verify that the signing key was generated on the device, not loaded from an external source.

This can be verified against the device attestation cert, which forms a chain back to the manufacturer.

```shell
# Use the same crt files from the previous step, create the CA chain
$ cat yubico.crt device.crt > chain.pem

# This cert was obtained from "cosign piv-tool attestation", the second cert
$ echo '-----BEGIN CERTIFICATE-----
MIICVTCCAT2gAwIBAgIQARF+TvIOm46Oc+FF3+YHITANBgkqhkiG9w0BAQsFADAh
MR8wHQYDVQQDDBZZdWJpY28gUElWIEF0dGVzdGF0aW9uMCAXDTE2MDMxNDAwMDAw
MFoYDzIwNTIwNDE3MDAwMDAwWjAlMSMwIQYDVQQDDBpZdWJpS2V5IFBJViBBdHRl
c3RhdGlvbiA5YzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBG2R72YMY5KlpWP
OuQj5ZgKoyyusj4S/uzKMSNyy5jv4DoR/EOnpVXAGSYAFGWPhl5TdLtf02rSPrHc
NgxEE4ejTjBMMBEGCisGAQQBgsQKAwMEAwUCBjAUBgorBgEEAYLECgMHBAYCBADH
kP4wEAYKKwYBBAGCxAoDCAQCAwIwDwYKKwYBBAGCxAoDCQQBAzANBgkqhkiG9w0B
AQsFAAOCAQEAeT5EXMm1PfVImtFinOPUsVY4tq2mPaZQ67//OiPisuSaF90YJIRJ
PyndeKHDpscFwN1h8XhACb6e6XAyswB//qMdt+2VEeJCFatcuUHki4Vb8plRkZNU
IDTbnZ3TnqY9eH4POmbHS9MmsDJPBFqCAvbX4hgHOiYmpim2tf4U562LMzpYU44c
rb9ZMlAhjlOHgft02Gduv2DK1THfUacMYR1L0p9WgCaRKAlAWsvyl3Xmfjf3NRJT
gzHKg/sREq1fns6kff5rj0kqZhuuhSYfOrhS3pRbMOEcKksymBwYbQpEgJYJndwO
uCPMJZqsNyWMmfksjulR9XAQvBCImkXncw==
-----END CERTIFICATE-----' > key.crt

$ openssl verify -CAfile chain.pem key.crt
key.crt: OK
```
