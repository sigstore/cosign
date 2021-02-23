# Copasetic

This directory contains an experimental OPA plugin (embedded OPA interpreter) that adds support for `cosign` and OCI.

## OCI

### `oci.manifest(ref) manifest`

This function takes a reference to an OCI image in a registry and returns the manifest.

```
> oci.manifest("gcr.io/dlorenc-vmtest2/demo:latest")
{
  "config": {
    "digest": "sha256:562b620db00eefdbc6d1728bc900ab4137aba4cfe2e66334bfe702258e4c6d6f",
    "mediaType": "application/vnd.docker.container.image.v1+json",
    "size": 3510
  },
  "layers": [
    {
      "digest": "sha256:83ee3a23efb7c75849515a6d46551c608b255d8402a4d3753752b88e0dc188fa",
      "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
      "size": 28565893
    },
    {
      "digest": "sha256:db98fc6f11f08950985a203e07755c3262c680d00084f601e7304b768c83b3b1",
      "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
      "size": 843
    },
    {
      "digest": "sha256:f611acd52c6cad803b06b5ba932e4aabd0f2d0d5a4d050c81de2832fcb781274",
      "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
      "size": 162
    },
    {
      "digest": "sha256:270c032c91133825ed533692ce3be5d63605a2415b86795601892bcad188a095",
      "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
      "size": 125
    }
  ],
  "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
  "schemaVersion": 2
}
```

### `oci.file(ref, path) file`

This function takes a reference to an OCI image in a registry and a path as inputs.
It returns the contents of the file at that path.

```
> oci.file("ubuntu:latest", "/etc/os-release")
"NAME=\"Ubuntu\"\nVERSION=\"20.04.1 LTS (Focal Fossa)\"\nID=ubuntu\nID_LIKE=debian\nPRETTY_NAME=\"Ubuntu 20.04.1 LTS\"\nVERSION_ID=\"20.04\"\nHOME_URL=\"https://www.ubuntu.com/\"\nSUPPORT_URL=\"https://help.ubuntu.com/\"\nBUG_REPORT_URL=\"https://bugs.launchpad.net/ubuntu/\"\nPRIVACY_POLICY_URL=\"https://www.ubuntu.com/legal/terms-and-policies/privacy-policy\"\nVERSION_CODENAME=focal\nUBUNTU_CODENAME=focal\n"
```

## Cosign

### `cosign.signatures(ref) []cosign.SignedPayload`

This function takes a reference to an OCI image in a registry and returns a list of `cosign.SignedPayload` structs.
It does not perform any verification or validation.

```
> cosign.signatures("gcr.io/dlorenc-vmtest2/foo")
[
  {
    "Base64Signature": "9mgUD6S8EqMeDJ9WZMTU7CdVXNOpJmOx5DiJJmuDEug5qxiq0LAcpEFa/Gk2uYdWOxtB9VX29req97M1WiQzDQ==",
    "Payload": "eyJDcml0aWNhbCI6eyJJZGVudGl0eSI6eyJkb2NrZXItcmVmZXJlbmNlIjoiIn0sIkltYWdlIjp7IkRvY2tlci1tYW5pZmVzdC1kaWdlc3QiOiI4N2VmNjBmNTU4YmFkNzliZWVhNjQyNWEzYjI4OTg5ZjAxZGQ0MTcxNjQxNTBhYjNiYWFiOThkY2JmMDRkZWY4In0sIlR5cGUiOiJjb3NpZ24gY29udGFpbmVyIHNpZ25hdHVyZSJ9LCJPcHRpb25hbCI6bnVsbH0="
  },
  {
    "Base64Signature": "YHhjPxaWr2OxnDsLGhZSnecLObVEBzGv8GUC4XWTgHpzfGMq4Lweo09dgWpfpEny4T6s+ZIZJmZxHSN+QLVvAg==",
    "Payload": "eyJDcml0aWNhbCI6eyJJZGVudGl0eSI6eyJkb2NrZXItcmVmZXJlbmNlIjoiIn0sIkltYWdlIjp7IkRvY2tlci1tYW5pZmVzdC1kaWdlc3QiOiI4N2VmNjBmNTU4YmFkNzliZWVhNjQyNWEzYjI4OTg5ZjAxZGQ0MTcxNjQxNTBhYjNiYWFiOThkY2JmMDRkZWY4In0sIlR5cGUiOiJjb3NpZ24gY29udGFpbmVyIHNpZ25hdHVyZSJ9LCJPcHRpb25hbCI6eyJmb28iOiJiYXIifX0="
  }
]
```

### `cosign.verify(ref, pubkey) []cosign.SignedPayload`

This function takes a reference to an OCI image in a registry and a base64 encoded PKIX public key.
It returns a list of verified `cosign.SignedPayload` structs.

```
> cosign.verify("gcr.io/dlorenc-vmtest2/demo", "MCowBQYDK2VwAyEAAh79z2geyybj2erSCpXpkgXc5mdg0fanVZjWNpwMLeA=")
[
  {
    "Base64Signature": "sR/r52vbIodlYxPBL5n0WK1sS7jJ/g4S423TJ3nT9WWp+/Z8UAkFjs/Mrh/KTPXePx73TSNabN8S+tu/A/BMAw==",
    "Payload": "eyJDcml0aWNhbCI6eyJJZGVudGl0eSI6eyJkb2NrZXItcmVmZXJlbmNlIjoiIn0sIkltYWdlIjp7IkRvY2tlci1tYW5pZmVzdC1kaWdlc3QiOiI5N2ZjMjIyY2VlNzk5MWI1YjA2MWQ0ZDRhZmRiNWYzNDI4ZmNiMGM5MDU0ZTE2OTAzMTM3ODZiZWZhMWU0ZTM2In0sIlR5cGUiOiJjb3NpZ24gY29udGFpbmVyIHNpZ25hdHVyZSJ9LCJPcHRpb25hbCI6eyJ0YWciOiJzaWduZWR0YWcifX0="
  },
  {
    "Base64Signature": "bMEsdC3m6Ca1rwBOY6lvqpOeBWo1lvu26DkHcsd6Upo91+aeUIVzOIzsZPFwUNXZ64p6RgLWGol2vP/3nrZNDw==",
    "Payload": "eyJDcml0aWNhbCI6eyJJZGVudGl0eSI6eyJkb2NrZXItcmVmZXJlbmNlIjoiIn0sIkltYWdlIjp7IkRvY2tlci1tYW5pZmVzdC1kaWdlc3QiOiI5N2ZjMjIyY2VlNzk5MWI1YjA2MWQ0ZDRhZmRiNWYzNDI4ZmNiMGM5MDU0ZTE2OTAzMTM3ODZiZWZhMWU0ZTM2In0sIlR5cGUiOiJjb3NpZ24gY29udGFpbmVyIHNpZ25hdHVyZSJ9LCJPcHRpb25hbCI6eyJzaWduZWR0YWciOiJzaWduZWR0YWcifX0="
  }
]
```
