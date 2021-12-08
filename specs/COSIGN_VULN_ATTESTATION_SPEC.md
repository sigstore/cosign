# Cosign Vulnerability Scan Record Attestation Specification

`Cosign` is heavily using [In-toto Attestations](https://github.com/in-toto/attestation) predicate models in its own
codebase. But this is not the only option you have while working with predicates in cosign. `Cosign` already defines its
own predicates: [Generic Predicate Specification](COSIGN_PREDICATE_SPEC.md). This `Vulnerability Scan`
attestation is one of them.

Let's talk a bit about the history of this specification. We first mentioned this idea
in [in-toto attestation](https://github.com/in-toto/attestation/issues/58) repository. So many people interested in this
issue, and shared ideas about which parts are necessary which parts are not to make that specification well-purposed.
There is an also cross [issue](https://github.com/sigstore/cosign/issues/442) on cosign side that we discussed on it.

And the final format for this is defined as follows:

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [
    {
      ...
    }
  ],
  // Predicate:
  "predicateType": "cosign.sigstore.dev/attestation/vuln/v1",
  "predicate": {
    "invocation": {
      "parameters": [],
      // [ "--format=json", "--skip-db-update" ]
      "uri": "",
      // https://github.com/developer-guy/alpine/actions/runs/1071875574
      "event_id": "",
      // 1071875574
      "builder.id": ""
      // GitHub Actions
    },
    "scanners": [
      {
        "uri": "",
        // pkg:github/aquasecurity/trivy@244fd47e07d1004f0aed9
        "version": "",
        // 0.19.2
        "db": {
          "uri": "",
          // pkg:github/aquasecurity/trivy-db/commit/4c76bb580b2736d67751410fa4ab66d2b6b9b27d
          "version": ""
          // "v1-2021080612"
        },
        "result": {}
      }
    ],
    "metadata": {
      "scanStartedOn": "",
      // 2021-08-06T17:45:50.52Z
      "scanFinishedOn": ""
      // 2021-08-06T17:50:50.52Z
    }
  }
}
```

## Fields

**scanners**

> There are lots of container image scanners such as Trivy, Grype, Clair, etc.
> This field describes about which one of them are used while scanning container image,
> and also give information about which Vulnerability DB is used while doing scan also with version informations attached.

**scanners.uri** string (ResourceURI), optional

> > URI indicating the identity of the source of the scanner.

**scanners.version** string (ResourceURI), optional

> The version of the scanner.

**scanners.db.uri** string (ResourceURI), optional

> URI indicating the identity of the source of the Vulnerability DB.

**scanners.db.version** string, optional

> The version of the Vulnerability DB.

**scanners.result** object

> This is the most important part of this field because it'll store the scan result as a whole. So, people might want
> to use this field to take decisions based on them by making use of Policy Engines tooling whether allow or deny these images.

**metadata.buildStartedOn string (Timestamp), required**

> The timestamp of when the build started.

**metadata.buildFinishedOn string (Timestamp), required**

> The timestamp of when the build completed.

```shell
$ trivy image -f json alpine:3.12
```

<details>

<summary>Scan Result</summary>

```json
{
  "SchemaVersion": 2,
  "ArtifactName": "alpine:3.12",
  "ArtifactType": "container_image",
  "Metadata": {
    "OS": {
      "Family": "alpine",
      "Name": "3.12.9"
    },
    "ImageID": "sha256:b0925e0819214cd29937af66dbaf0e6fe239997faea60922cc890f9984512507",
    "DiffIDs": [
      "sha256:eb4bde6b29a6746e0779f80a09ca6f0806de61475059f7d56d6e20f6cc2e15f7"
    ],
    "RepoTags": [
      "alpine:3.12"
    ],
    "RepoDigests": [
      "alpine@sha256:d9459083f962de6bd980ae6a05be2a4cf670df6a1d898157bceb420342bec280"
    ],
    "ImageConfig": {
      "architecture": "amd64",
      "container": "385e1cc96cc7482dfb6847e293bb24baecd3f48a49791b9b45e297204b160287",
      "created": "2021-11-12T17:20:08.442217528Z",
      "docker_version": "20.10.7",
      "history": [
        {
          "created": "2021-11-12T17:20:08.190319702Z",
          "created_by": "/bin/sh -c #(nop) ADD file:8f5bc5ce64ef781adadca88e4004e17affc72e6f20dbd08b9c478def12fe1dd3 in / "
        },
        {
          "created": "2021-11-12T17:20:08.442217528Z",
          "created_by": "/bin/sh -c #(nop)  CMD [\"/bin/sh\"]",
          "empty_layer": true
        }
      ],
      "os": "linux",
      "rootfs": {
        "type": "layers",
        "diff_ids": [
          "sha256:eb4bde6b29a6746e0779f80a09ca6f0806de61475059f7d56d6e20f6cc2e15f7"
        ]
      },
      "config": {
        "Cmd": [
          "/bin/sh"
        ],
        "Env": [
          "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        ],
        "Image": "sha256:7d1c1e4b291dc9519b43a2b9c9330655927f6dfde90d36ef5fd16b2ae0f28bbc"
      }
    }
  },
  "Results": [
    {
      "Target": "alpine:3.12 (alpine 3.12.9)",
      "Class": "os-pkgs",
      "Type": "alpine",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2021-28831",
          "PkgName": "busybox",
          "InstalledVersion": "1.31.1-r21",
          "FixedVersion": "1.32.1-r4",
          "Layer": {
            "Digest": "sha256:8572bc8fb8a32061648dd183b2c0451c82be1bd053a4ea8fae991436b92faebb",
            "DiffID": "sha256:eb4bde6b29a6746e0779f80a09ca6f0806de61475059f7d56d6e20f6cc2e15f7"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-28831",
          "Title": "busybox: invalid free or segmentation fault via malformed gzip data",
          "Description": "decompress_gunzip.c in BusyBox through 1.32.1 mishandles the error bit on the huft_build result pointer, with a resultant invalid free or segmentation fault, via malformed gzip data.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-755"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V2Score": 5,
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            }
          },
          "References": [
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-28831",
            "https://git.busybox.net/busybox/commit/?id=f25d254dfd4243698c31a4f3153d4ac72aa9e9bd",
            "https://lists.debian.org/debian-lts-announce/2021/04/msg00001.html",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/3UDQGJRECXFS5EZVDH2OI45FMO436AC4/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/Z7ZIFKPRR32ZYA3WAA2NXFA3QHHOU6FJ/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZASBW7QRRLY5V2R44MQ4QQM4CZIDHM2U/",
            "https://security.gentoo.org/glsa/202105-09",
            "https://ubuntu.com/security/notices/USN-5179-1"
          ],
          "PublishedDate": "2021-03-19T05:15:00Z",
          "LastModifiedDate": "2021-05-26T10:15:00Z"
        },
        {
          "VulnerabilityID": "CVE-2021-28831",
          "PkgName": "ssl_client",
          "InstalledVersion": "1.31.1-r21",
          "FixedVersion": "1.32.1-r4",
          "Layer": {
            "Digest": "sha256:8572bc8fb8a32061648dd183b2c0451c82be1bd053a4ea8fae991436b92faebb",
            "DiffID": "sha256:eb4bde6b29a6746e0779f80a09ca6f0806de61475059f7d56d6e20f6cc2e15f7"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-28831",
          "Title": "busybox: invalid free or segmentation fault via malformed gzip data",
          "Description": "decompress_gunzip.c in BusyBox through 1.32.1 mishandles the error bit on the huft_build result pointer, with a resultant invalid free or segmentation fault, via malformed gzip data.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-755"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V2Score": 5,
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            }
          },
          "References": [
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-28831",
            "https://git.busybox.net/busybox/commit/?id=f25d254dfd4243698c31a4f3153d4ac72aa9e9bd",
            "https://lists.debian.org/debian-lts-announce/2021/04/msg00001.html",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/3UDQGJRECXFS5EZVDH2OI45FMO436AC4/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/Z7ZIFKPRR32ZYA3WAA2NXFA3QHHOU6FJ/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZASBW7QRRLY5V2R44MQ4QQM4CZIDHM2U/",
            "https://security.gentoo.org/glsa/202105-09",
            "https://ubuntu.com/security/notices/USN-5179-1"
          ],
          "PublishedDate": "2021-03-19T05:15:00Z",
          "LastModifiedDate": "2021-05-26T10:15:00Z"
        }
      ]
    }
  ]
}
```

</details>

Here is an example predicate containing a vulnerability scan result above:

```json
{
  "predicate": {
    "invocation": {
      "parameters": [
        "--format=json"
      ],
      "uri": "https://github.com/developer-guy/alpine/actions/runs/1071875574",
      "event_id": "1071875574",
      "builder.id": "github actions"
    },
    "scanners": [
      {
        "uri": "pkg:github/aquasecurity/trivy@244fd47e07d1004f0aed9",
        "version": "0.19.2",
        "db": {
          "uri": "pkg:github/aquasecurity/trivy-db/commit/4c76bb580b2736d67751410fa4ab66d2b6b9b27d",
          "version": "v1-2021080612"
        },
        "result": {
          "SchemaVersion": 2,
          "ArtifactName": "alpine:3.12",
          "ArtifactType": "container_image",
          "Metadata": {
            "OS": {
              "Family": "alpine",
              "Name": "3.12.9"
            },
            "ImageID": "sha256:b0925e0819214cd29937af66dbaf0e6fe239997faea60922cc890f9984512507",
            "DiffIDs": [
              "sha256:eb4bde6b29a6746e0779f80a09ca6f0806de61475059f7d56d6e20f6cc2e15f7"
            ],
            "RepoTags": [
              "alpine:3.12"
            ],
            "RepoDigests": [
              "alpine@sha256:d9459083f962de6bd980ae6a05be2a4cf670df6a1d898157bceb420342bec280"
            ],
            "ImageConfig": {
              "architecture": "amd64",
              "container": "385e1cc96cc7482dfb6847e293bb24baecd3f48a49791b9b45e297204b160287",
              "created": "2021-11-12T17:20:08.442217528Z",
              "docker_version": "20.10.7",
              "history": [
                {
                  "created": "2021-11-12T17:20:08.190319702Z",
                  "created_by": "/bin/sh -c #(nop) ADD file:8f5bc5ce64ef781adadca88e4004e17affc72e6f20dbd08b9c478def12fe1dd3 in / "
                },
                {
                  "created": "2021-11-12T17:20:08.442217528Z",
                  "created_by": "/bin/sh -c #(nop)  CMD [\"/bin/sh\"]",
                  "empty_layer": true
                }
              ],
              "os": "linux",
              "rootfs": {
                "type": "layers",
                "diff_ids": [
                  "sha256:eb4bde6b29a6746e0779f80a09ca6f0806de61475059f7d56d6e20f6cc2e15f7"
                ]
              },
              "config": {
                "Cmd": [
                  "/bin/sh"
                ],
                "Env": [
                  "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
                ],
                "Image": "sha256:7d1c1e4b291dc9519b43a2b9c9330655927f6dfde90d36ef5fd16b2ae0f28bbc"
              }
            }
          },
          "Results": [
            {
              "Target": "alpine:3.12 (alpine 3.12.9)",
              "Class": "os-pkgs",
              "Type": "alpine",
              "Vulnerabilities": [
                {
                  "VulnerabilityID": "CVE-2021-28831",
                  "PkgName": "busybox",
                  "InstalledVersion": "1.31.1-r21",
                  "FixedVersion": "1.32.1-r4",
                  "Layer": {
                    "Digest": "sha256:8572bc8fb8a32061648dd183b2c0451c82be1bd053a4ea8fae991436b92faebb",
                    "DiffID": "sha256:eb4bde6b29a6746e0779f80a09ca6f0806de61475059f7d56d6e20f6cc2e15f7"
                  },
                  "SeveritySource": "nvd",
                  "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-28831",
                  "Title": "busybox: invalid free or segmentation fault via malformed gzip data",
                  "Description": "decompress_gunzip.c in BusyBox through 1.32.1 mishandles the error bit on the huft_build result pointer, with a resultant invalid free or segmentation fault, via malformed gzip data.",
                  "Severity": "HIGH",
                  "CweIDs": [
                    "CWE-755"
                  ],
                  "CVSS": {
                    "nvd": {
                      "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
                      "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                      "V2Score": 5,
                      "V3Score": 7.5
                    },
                    "redhat": {
                      "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                      "V3Score": 7.5
                    }
                  },
                  "References": [
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-28831",
                    "https://git.busybox.net/busybox/commit/?id=f25d254dfd4243698c31a4f3153d4ac72aa9e9bd",
                    "https://lists.debian.org/debian-lts-announce/2021/04/msg00001.html",
                    "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/3UDQGJRECXFS5EZVDH2OI45FMO436AC4/",
                    "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/Z7ZIFKPRR32ZYA3WAA2NXFA3QHHOU6FJ/",
                    "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZASBW7QRRLY5V2R44MQ4QQM4CZIDHM2U/",
                    "https://security.gentoo.org/glsa/202105-09",
                    "https://ubuntu.com/security/notices/USN-5179-1"
                  ],
                  "PublishedDate": "2021-03-19T05:15:00Z",
                  "LastModifiedDate": "2021-05-26T10:15:00Z"
                },
                {
                  "VulnerabilityID": "CVE-2021-28831",
                  "PkgName": "ssl_client",
                  "InstalledVersion": "1.31.1-r21",
                  "FixedVersion": "1.32.1-r4",
                  "Layer": {
                    "Digest": "sha256:8572bc8fb8a32061648dd183b2c0451c82be1bd053a4ea8fae991436b92faebb",
                    "DiffID": "sha256:eb4bde6b29a6746e0779f80a09ca6f0806de61475059f7d56d6e20f6cc2e15f7"
                  },
                  "SeveritySource": "nvd",
                  "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-28831",
                  "Title": "busybox: invalid free or segmentation fault via malformed gzip data",
                  "Description": "decompress_gunzip.c in BusyBox through 1.32.1 mishandles the error bit on the huft_build result pointer, with a resultant invalid free or segmentation fault, via malformed gzip data.",
                  "Severity": "HIGH",
                  "CweIDs": [
                    "CWE-755"
                  ],
                  "CVSS": {
                    "nvd": {
                      "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
                      "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                      "V2Score": 5,
                      "V3Score": 7.5
                    },
                    "redhat": {
                      "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                      "V3Score": 7.5
                    }
                  },
                  "References": [
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-28831",
                    "https://git.busybox.net/busybox/commit/?id=f25d254dfd4243698c31a4f3153d4ac72aa9e9bd",
                    "https://lists.debian.org/debian-lts-announce/2021/04/msg00001.html",
                    "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/3UDQGJRECXFS5EZVDH2OI45FMO436AC4/",
                    "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/Z7ZIFKPRR32ZYA3WAA2NXFA3QHHOU6FJ/",
                    "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZASBW7QRRLY5V2R44MQ4QQM4CZIDHM2U/",
                    "https://security.gentoo.org/glsa/202105-09",
                    "https://ubuntu.com/security/notices/USN-5179-1"
                  ],
                  "PublishedDate": "2021-03-19T05:15:00Z",
                  "LastModifiedDate": "2021-05-26T10:15:00Z"
                }
              ]
            }
          ]
        }
      }
    ],
    "metadata": {
      "scanStartedOn": "2021-08-06T17:45:50.52Z",
      "scanFinishedOn": "2021-08-06T17:50:50.52Z"
    }
  }
}
```

