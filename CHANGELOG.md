# v1.7.0

## Enhancements

* sign: set the oidc redirect uri (https://github.com/sigstore/cosign/pull/1675)
* Use ValidatePubKey from sigstore/sigstore (https://github.com/sigstore/cosign/pull/1676)
* Remove the hardcoded sigstore audience (https://github.com/sigstore/cosign/pull/1698)
* verify: remove extra calls to rekor for verify and verify-blob (https://github.com/sigstore/cosign/pull/1694)
* add leaf hash verification (https://github.com/sigstore/cosign/pull/1688)
* cosign clean: Don't log failure if the registry responds with 404 (https://github.com/sigstore/cosign/pull/1687)
* Update error message for verify/verify attestation (https://github.com/sigstore/cosign/pull/1686)
* change file_name_template to PackageName (https://github.com/sigstore/cosign/pull/1683)
* Make `cosign copy` copy metadata attached to child images. (https://github.com/sigstore/cosign/pull/1682)
* Add support for cert and cert chain flags with PKCS11 tokens (https://github.com/sigstore/cosign/pull/1671)
* Find all valid entries in verify-blob (https://github.com/sigstore/cosign/pull/1673)
* Refactor based on discussions in #1650 (https://github.com/sigstore/cosign/pull/1674)
* feat: add ability to override registry keychain (https://github.com/sigstore/cosign/pull/1666)
* Add specific suffixes mediaTypes to sboms (https://github.com/sigstore/cosign/pull/1663)
* Add certificate chain flag for signing (https://github.com/sigstore/cosign/pull/1656)
* First batch of followups to #1650 (https://github.com/sigstore/cosign/pull/1664)
* Add support for certificate chain to verify certificate (https://github.com/sigstore/cosign/pull/1659)
* Use syscall.Stdin for input handle. Fixes #1153 (https://github.com/sigstore/cosign/pull/1657)
* Shorten example OAuth URL (https://github.com/sigstore/cosign/pull/1661)
* Prompt user before running `cosign clean` (https://github.com/sigstore/cosign/pull/1649)
* Add support for intermediate certificates when verifiying (https://github.com/sigstore/cosign/pull/1631)
* feat: tree command utility (https://github.com/sigstore/cosign/pull/1603)
* Validate authority keys (https://github.com/sigstore/cosign/pull/1623)
* improve cosigned validation error messages (https://github.com/sigstore/cosign/pull/1618)
* Init entity from ociremote when signing a digest ref (https://github.com/sigstore/cosign/pull/1616)
* Add two env variables. One for using Rekor public key from OOB and (https://github.com/sigstore/cosign/pull/1610)
* Ensure entry is removed from CM on secret error. (https://github.com/sigstore/cosign/pull/1605)
* Validate a public key in a secret is valid. (https://github.com/sigstore/cosign/pull/1602)
* Add public key validation (https://github.com/sigstore/cosign/pull/1598)
* Add ability to inline secrets from SecretRef to configmap. (https://github.com/sigstore/cosign/pull/1595)
* 1417 policy validations (https://github.com/sigstore/cosign/pull/1548)
* Support deletion of ClusterImagePolicy (https://github.com/sigstore/cosign/pull/1580)
* Start of the necessary pieces to get #1418 and #1419 implemented (https://github.com/sigstore/cosign/pull/1562)

## Bug Fixes

* Fix handling of policy in verify-attestation (https://github.com/sigstore/cosign/pull/1672)
* Fix relative paths in Gitub OIDC blob test (https://github.com/sigstore/cosign/pull/1677)
* fix build date format for version command (https://github.com/sigstore/cosign/pull/1644)
* Fix 1608, 1613 (https://github.com/sigstore/cosign/pull/1617)
* Fix copy/paste mistake in repo name. (https://github.com/sigstore/cosign/pull/1600)
* Fix #1592 move authorities as siblings of images. (https://github.com/sigstore/cosign/pull/1593)
* Fix piping 'cosign verify' using fulcio/rekor (https://github.com/sigstore/cosign/pull/1590)
* Fix #1583 #1582. Disallow regex now until implemented. (https://github.com/sigstore/cosign/pull/1584)
* Don't lowercase input image refs, just fail (https://github.com/sigstore/cosign/pull/1586)

## Documention

* Document Elastic container registry support (https://github.com/sigstore/cosign/pull/1641)
* FUN.md broke when RecordObj changed to HashedRecordObj (https://github.com/sigstore/cosign/pull/1633)
* Add example using AWS Key Management Service (KMS) (https://github.com/sigstore/cosign/pull/1564)


## Others

* Use the github actions from sigstore/scaffolding. (https://github.com/sigstore/cosign/pull/1699)
* Bump google.golang.org/api from 0.73.0 to 0.74.0 (https://github.com/sigstore/cosign/pull/1695)
* Bump github/codeql-action from 1.1.5 to 2.1.6 (https://github.com/sigstore/cosign/pull/1690)
* Bump actions/cache from 3.0.0 to 3.0.1 (https://github.com/sigstore/cosign/pull/1689)
* Add e2e test for attest / verify-attestation (https://github.com/sigstore/cosign/pull/1685)
* Use cosign @ HEAD for Github OIDC sign blob test (https://github.com/sigstore/cosign/pull/1678)
* Bump mikefarah/yq from 4.23.1 to 4.24.2 (https://github.com/sigstore/cosign/pull/1670)
* remove replace directive (https://github.com/sigstore/cosign/pull/1669)
* update font when output the cosign version (https://github.com/sigstore/cosign/pull/1668)
* Use ClusterImagePolicy with Keyless + e2e tests for CIP with kind (https://github.com/sigstore/cosign/pull/1650)
* Bump google.golang.org/protobuf from 1.27.1 to 1.28.0 (https://github.com/sigstore/cosign/pull/1646)
* Bump mikefarah/yq from 4.22.1 to 4.23.1 (https://github.com/sigstore/cosign/pull/1639)
* Bump actions/cache from 2.1.7 to 3 (https://github.com/sigstore/cosign/pull/1640)
* Bump github.com/go-openapi/runtime from 0.23.2 to 0.23.3 (https://github.com/sigstore/cosign/pull/1638)
* Add extra label and change the latest tag to unstable for non tagged releases (https://github.com/sigstore/cosign/pull/1637)
* push latest tag when building a release (https://github.com/sigstore/cosign/pull/1636)
* update crane to v0.8.0 release (https://github.com/sigstore/cosign/pull/1635)
* Bump github.com/xanzy/go-gitlab from 0.59.0 to 0.60.0 (https://github.com/sigstore/cosign/pull/1634)
* Included OpenSSF Best Practices Badge (https://github.com/sigstore/cosign/pull/1628)
* Use latest knative/pkg's configmap informer (https://github.com/sigstore/cosign/pull/1615)
* Bump github.com/stretchr/testify from 1.7.0 to 1.7.1 (https://github.com/sigstore/cosign/pull/1621)
* Bump google.golang.org/api from 0.72.0 to 0.73.0 (https://github.com/sigstore/cosign/pull/1619)
* Bump github/codeql-action from 1.1.4 to 1.1.5 (https://github.com/sigstore/cosign/pull/1622)
* Bump ecr-login to pick up WithLogger rename (https://github.com/sigstore/cosign/pull/1624)
* Bump to knative pkg 1.3 (https://github.com/sigstore/cosign/pull/1614)
* Bump google.golang.org/api from 0.71.0 to 0.72.0 (https://github.com/sigstore/cosign/pull/1612)
* Use reusuable release workflow in sigstore/sigstore (https://github.com/sigstore/cosign/pull/1599)
* Bump github.com/spiffe/go-spiffe/v2 from 2.0.0-beta.12 to 2.0.0 (https://github.com/sigstore/cosign/pull/1597)
* Bump mikefarah/yq from 4.21.1 to 4.22.1 (https://github.com/sigstore/cosign/pull/1589)
* Bump google.golang.org/grpc from 1.44.0 to 1.45.0 (https://github.com/sigstore/cosign/pull/1587)
* Bump github.com/spf13/cobra from 1.3.0 to 1.4.0 (https://github.com/sigstore/cosign/pull/1588)
* Bump github.com/xanzy/go-gitlab from 0.58.0 to 0.59.0 (https://github.com/sigstore/cosign/pull/1579)
* Bump google-github-actions/setup-gcloud from 0.5.1 to 0.6.0 (https://github.com/sigstore/cosign/pull/1578)
* Bump github.com/hashicorp/go-hclog from 1.1.0 to 1.2.0 (https://github.com/sigstore/cosign/pull/1576)
* Bump google.golang.org/api from 0.70.0 to 0.71.0 (https://github.com/sigstore/cosign/pull/1577)
* Bump github/codeql-action from 1.1.3 to 1.1.4 (https://github.com/sigstore/cosign/pull/1565)
* add definition for artifact hub to verify the ownership (https://github.com/sigstore/cosign/pull/1563)
* Bump sigstore/cosign-installer from 2.0.1 to 2.1.0 (https://github.com/sigstore/cosign/pull/1561)
* Bump github.com/go-openapi/runtime from 0.23.1 to 0.23.2 (https://github.com/sigstore/cosign/pull/1559)
* Bump github.com/xanzy/go-gitlab from 0.57.0 to 0.58.0 (https://github.com/sigstore/cosign/pull/1560)
* Update hashicorp/parseutil to v0.1.3. (https://github.com/sigstore/cosign/pull/1557)
* Mirror signed release images from GCR to GHCR as part of release with Cloud Build. (https://github.com/sigstore/cosign/pull/1547)
* Bump github.com/xanzy/go-gitlab from 0.56.0 to 0.57.0 (https://github.com/sigstore/cosign/pull/1552)
* Bump actions/upload-artifact from 2.3.1 to 3 (https://github.com/sigstore/cosign/pull/1553)
* pkcs11: fix build instructions (https://github.com/sigstore/cosign/pull/1550)
* Update images for release job (https://github.com/sigstore/cosign/pull/1551)

## Contributors

* Adam A.G. Shamblin (@coyote240)
* Adolfo García Veytia (@puerco)
* Asra Ali (@asraa)
* Batuhan Apaydın (@developer-guy)
* Carlos Tadeu Panato Junior (@cpanato)
* Dan Lorenc (@dlorenc)
* Davi Garcia (@davivcgarcia)
* Hayden Blauzvern (@haydentherapper)
* Hector Fernandez (@hectorj2f)
* James Strong (@strongjz)
* Jason Hall (@imjasonh)
* Kavitha (@kkavitha)
* Kenny Leung (@k4leung4)
* Luiz Carvalho (@lcarva)
* Marco Franssen (@marcofranssen)
* Mark Percival (@mdp)
* Matt Moore (@mattmoor)
* Maxime Gréau (@mgreau)
* Mitch Thomas (@MitchellJThomas)
* Naveen Srinivasan (@naveensrinivasan)
* Nghia Tran (@tcnghia)
* Priya Wadhwa (@priyawadhwa)
* Radoslav Gerganov (@rgerganov)
* Thomas Strömberg (@tstromberg)
* Ville Aikas (@vaikas)
* noamichael (@noamichael)

# v1.6.0

## Security Fixes

* CVE-2022-23649 - Make sure signature in Rekor bundle matches signature being verified

## Enhancements

* Change Fulcio URL default to be fulcio.sigstore.dev (https://github.com/sigstore/cosign/pull/1529)
* Add CertExtensions func to extract all extensions (https://github.com/sigstore/cosign/pull/1515)
* Add a dummy.go file to allow vendoring config (https://github.com/sigstore/cosign/pull/1520)
* Add skeleton reconciler for cosigned API CRD. (https://github.com/sigstore/cosign/pull/1513)
* use v6 api calls (https://github.com/sigstore/cosign/pull/1511)
* This sets up the scaffolding for the `cosigned` CRD types. (https://github.com/sigstore/cosign/pull/1504)
* add correct layer media type to attach attestation (https://github.com/sigstore/cosign/pull/1503)
* Pick up some of the shared workflows (https://github.com/sigstore/cosign/pull/1490)
* feat: support other types in copy cmd (https://github.com/sigstore/cosign/pull/1493)
* Pick up a change to quiet ECR-login logging. (https://github.com/sigstore/cosign/pull/1491)
* Merge pull request from GHSA-ccxc-vr6p-4858
* fix(sign): refactor unsupported provider log (https://github.com/sigstore/cosign/pull/1464)
* Print message when verifying with old TUF targets (https://github.com/sigstore/cosign/pull/1468)
* convert release cosigned to also generate yaml artifact. (https://github.com/sigstore/cosign/pull/1453)
* Streamline `SignBlobCmd` API with `SignCmd` (https://github.com/sigstore/cosign/pull/1454)
* feat: add -buildid= to ldflags (https://github.com/sigstore/cosign/pull/1451)
* Fetch verification targets by TUF custom metadata (https://github.com/sigstore/cosign/pull/1423)
* feat: fig autocomplete feature (https://github.com/sigstore/cosign/pull/1360)
* Improve log lines to match with implementation (https://github.com/sigstore/cosign/pull/1432)
* use the upstream kubernetes version lib and ldflags (https://github.com/sigstore/cosign/pull/1413)
* feat: enhance clean cmd capability (https://github.com/sigstore/cosign/pull/1430)
* Remove TUF timestamp from OCI signature bundle (https://github.com/sigstore/cosign/pull/1428)
* Allow `PassFunc` to be `nil` (https://github.com/sigstore/cosign/pull/1426)
* Add ability to override the Spiffe socket via environmental variable: (https://github.com/sigstore/cosign/pull/1421)
* Improve error message when image is not found in registry (https://github.com/sigstore/cosign/pull/1410)
* add root status output (https://github.com/sigstore/cosign/pull/1404)
* feat: login command (https://github.com/sigstore/cosign/pull/1398)
* Minor refactor to verify SCT and Rekor entry with multiple keys (https://github.com/sigstore/cosign/pull/1396)
* Add Cosign logo to README (https://github.com/sigstore/cosign/pull/1395)
* Add `--timeout` support to `sign` command (https://github.com/sigstore/cosign/pull/1379)

## Bug Fixes

* bug fix: import ed25519 keys and fix error handling (https://github.com/sigstore/cosign/pull/1518)
* Fix wording on attach attestation help (https://github.com/sigstore/cosign/pull/1480)
* fix(sign): kms unspported message (https://github.com/sigstore/cosign/pull/1475)
* Fix incorrect error check when verifying SCT (https://github.com/sigstore/cosign/pull/1422)
* make imageRef lowercase before parsing (https://github.com/sigstore/cosign/pull/1409)
* Add a new line after password input (https://github.com/sigstore/cosign/pull/1407)
* Fix comparison in replace option for attestation (https://github.com/sigstore/cosign/pull/1366)

## Documention

* Quay OCI Support in README (https://github.com/sigstore/cosign/pull/1539)
* feat: nominate Dentrax as codeowner (https://github.com/sigstore/cosign/pull/1492)
* add initial changelog for 1.5.2 (https://github.com/sigstore/cosign/pull/1483)
* fix tkn link in readme (https://github.com/sigstore/cosign/pull/1459)
* Add FEATURES.md and DEPRECATIONS.md (https://github.com/sigstore/cosign/pull/1429)
* Update the cosign keyless documentation to point to the GA release. (https://github.com/sigstore/cosign/pull/1427)
* Fix link for SECURITY.md (https://github.com/sigstore/cosign/pull/1399)

## Others

* Consistent parenthesis use in Makefile (https://github.com/sigstore/cosign/pull/1541)
* Bump github.com/xanzy/go-gitlab from 0.55.1 to 0.56.0 (https://github.com/sigstore/cosign/pull/1538)
* add rpm,deb and apks for cosign packages (https://github.com/sigstore/cosign/pull/1537)
* update github.com/hashicorp/vault/sdk, codegen and go module to 1.17 (https://github.com/sigstore/cosign/pull/1536)
* images: remove --bare flags that conflict with --base-import-paths (https://github.com/sigstore/cosign/pull/1533)
* Bump actions/checkout from 2 to 3 (https://github.com/sigstore/cosign/pull/1531)
* Add codecov as github action, set permissions to read content only (https://github.com/sigstore/cosign/pull/1530)
* Bump github.com/spiffe/go-spiffe/v2 from 2.0.0-beta.11 to 2.0.0-beta.12 (https://github.com/sigstore/cosign/pull/1528)
* Bump actions/setup-go from 2 to 3 (https://github.com/sigstore/cosign/pull/1527)
* Bump golangci/golangci-lint-action from 3.0.0 to 3.1.0 (https://github.com/sigstore/cosign/pull/1526)
* Bump mikefarah/yq from 4.20.2 to 4.21.1 (https://github.com/sigstore/cosign/pull/1525)
* Bump github.com/secure-systems-lab/go-securesystemslib (https://github.com/sigstore/cosign/pull/1524)
* chore(ci): add artifact hub support (https://github.com/sigstore/cosign/pull/1522)
* optimize codeql speed by using caching and tracing (https://github.com/sigstore/cosign/pull/1519)
* Bump golangci/golangci-lint-action from 2.5.2 to 3 (https://github.com/sigstore/cosign/pull/1516)
* Bump github/codeql-action from 1.1.2 to 1.1.3 (https://github.com/sigstore/cosign/pull/1512)
* Bump mikefarah/yq from 4.16.2 to 4.20.2 (https://github.com/sigstore/cosign/pull/1510)
* Bump github.com/go-openapi/runtime from 0.23.0 to 0.23.1 (https://github.com/sigstore/cosign/pull/1507)
* Bump go.uber.org/zap from 1.20.0 to 1.21.0 (https://github.com/sigstore/cosign/pull/1509)
* Bump actions/setup-go from 2.1.5 to 2.2.0 (https://github.com/sigstore/cosign/pull/1495)
* Bump google-github-actions/auth from 0.4.4 to 0.6.0 (https://github.com/sigstore/cosign/pull/1501)
* Bump ossf/scorecard-action (https://github.com/sigstore/cosign/pull/1502)
* Bump google.golang.org/api from 0.69.0 to 0.70.0 (https://github.com/sigstore/cosign/pull/1500)
* Bump sigstore/cosign-installer from 1.4.1 to 2.0.1 (https://github.com/sigstore/cosign/pull/1496)
* Bump actions/github-script from 4.1.1 to 6 (https://github.com/sigstore/cosign/pull/1497)
* Update github/codeql-action requirement to d39d5d5c9707b926d517b1b292905ef4c03aa777 (https://github.com/sigstore/cosign/pull/1498)
* Bump google-github-actions/setup-gcloud from 0.3.0 to 0.5.1 (https://github.com/sigstore/cosign/pull/1499)
* chore(makefile): use kocache, convert publish to build (https://github.com/sigstore/cosign/pull/1488)
* Bump cloud.google.com/go/storage from 1.20.0 to 1.21.0 (https://github.com/sigstore/cosign/pull/1481)
* update changelog (https://github.com/sigstore/cosign/pull/1485)
* fix lint (https://github.com/sigstore/cosign/pull/1484)
* update go-tuf and simplify TUF client code (https://github.com/sigstore/cosign/pull/1455)
* Bump sigstore/sigstore to pick up the kms change and the monkey-patch work. (https://github.com/sigstore/cosign/pull/1479)
* refactor release cloudbuild job (https://github.com/sigstore/cosign/pull/1476)
* increase timeout for goreleaser snapshot (https://github.com/sigstore/cosign/pull/1473)
* Double goreleaser timeout (https://github.com/sigstore/cosign/pull/1472)
* Bump google.golang.org/api from 0.68.0 to 0.69.0 (https://github.com/sigstore/cosign/pull/1469)
* tests: `/bin/bash` -> `/usr/bin/env bash` (https://github.com/sigstore/cosign/pull/1470)
* Bump the gitlab library and add a nil opt for the API change. (https://github.com/sigstore/cosign/pull/1466)
* Bump webhook timeout. (https://github.com/sigstore/cosign/pull/1465)
* update cross-build to use go 1.17.7 (https://github.com/sigstore/cosign/pull/1446)
* Bump go-containerregistry, pick up new features (https://github.com/sigstore/cosign/pull/1442)
* update cross-build image which adds goimports (https://github.com/sigstore/cosign/pull/1435)
* Bump google.golang.org/api from 0.67.0 to 0.68.0 (https://github.com/sigstore/cosign/pull/1434)
* Skip the ReadWrite test that flakes on Windows. (https://github.com/sigstore/cosign/pull/1415)
* Bump github.com/go-openapi/strfmt from 0.21.1 to 0.21.2 (https://github.com/sigstore/cosign/pull/1411)
* Bump github.com/go-openapi/runtime from 0.22.0 to 0.23.0 (https://github.com/sigstore/cosign/pull/1412)
* Bump cloud.google.com/go/storage from 1.19.0 to 1.20.0 (https://github.com/sigstore/cosign/pull/1403)
* Bump google.golang.org/api from 0.66.0 to 0.67.0 (https://github.com/sigstore/cosign/pull/1402)
* Bump cuelang.org/go from 0.4.1 to 0.4.2 (https://github.com/sigstore/cosign/pull/1401)
* update cosign and cross-build image for the release job (https://github.com/sigstore/cosign/pull/1400)
* Bump github.com/xanzy/go-gitlab from 0.54.3 to 0.54.4 (https://github.com/sigstore/cosign/pull/1391)
* Bump github.com/go-openapi/swag from 0.20.0 to 0.21.1 (https://github.com/sigstore/cosign/pull/1386)
* Fix double `time` import in e2e tests (https://github.com/sigstore/cosign/pull/1388)
* Bump github.com/go-openapi/swag from 0.19.15 to 0.20.0 (https://github.com/sigstore/cosign/pull/1383)
* Bump github.com/go-openapi/runtime from 0.21.1 to 0.22.0 (https://github.com/sigstore/cosign/pull/1382)
* add changelog for 1.5.1 release (https://github.com/sigstore/cosign/pull/1376)

## Contributors

* Andrew Block (@sabre1041)
* Asra Ali (@asraa)
* Batuhan Apaydın (@developer-guy)
* Blake Burkhart (@bburky)
* Bob Callaway (@bobcallaway)
* Carlos Tadeu Panato Junior (@cpanato)
* Christian Kotzbauer (@ckotzbauer)
* Christopher Angelo Phillips (@spiffcs)
* Dan Lorenc (@dlorenc)
* Dan Luhring (@luhring)
* Furkan Türkal (@Dentrax)
* Hayden Blauzvern (@haydentherapper)
* Jason Hall (@imjasonh)
* Josh Dolitsky (@jdolitsky)
* Kenny Leung (@k4leung4)
* Matt Moore (@mattmoor)
* Marco Franssen (@marcofranssen)
* Nathan Smith (@nsmith5)
* Priya Wadhwa (@priyawadhwa)
* Sascha Grunert (@saschagrunert)
* Scott Nichols (@n3wscott)
* Teppei Fukuda (@knqyf263)
* Ville Aikas (@vaikas)
* Yongxuan Zhang (@Yongxuanzhang)
* Zack Newman (@znewman01)

# v1.5.2

## Security Fixes

* CVE-2022-23649 - Make sure signature in Rekor bundle matches signature being verified

## Others

* refactor release cloudbuild job (https://github.com/sigstore/cosign/pull/1476)
* increase timeout for goreleaser snapshot (https://github.com/sigstore/cosign/pull/1473)
* Double goreleaser timeout (https://github.com/sigstore/cosign/pull/1472)
* Bump webhook timeout. (https://github.com/sigstore/cosign/pull/1465)
* convert release cosigned to also generate yaml artifact. (https://github.com/sigstore/cosign/pull/1453)
* feat: add -buildid= to ldflags (https://github.com/sigstore/cosign/pull/1451)
* update cross-build to use go 1.17.7 (https://github.com/sigstore/cosign/pull/1446)

## Contributors

* Batuhan Apaydın (@developer-guy)
* Carlos Tadeu Panato Junior (@cpanato)
* Dan Lorenc (@dlorenc)
* Kenny Leung (@k4leung4)
* Matt Moore (@mattmoor)
* Nathan Smith (@nsmith5)
* Priya Wadhwa (@priyawadhwa)
* Zack Newman (@znewman01)

# v1.5.1

## Bug Fixes

* add check to make sure the go modules are in sync (https://github.com/sigstore/cosign/pull/1369)
* Update verify-blob to support DSSEs (https://github.com/sigstore/cosign/pull/1355)

## Documention

* docs: verify-attestation cue and rego policy doc (https://github.com/sigstore/cosign/pull/1362)
* README: fix link to race conditions (https://github.com/sigstore/cosign/pull/1367)

## Others

* Bump sigstore/sigstore to pick up oidc login for vault. (https://github.com/sigstore/cosign/pull/1377)
* Bump google.golang.org/api from 0.65.0 to 0.66.0 (https://github.com/sigstore/cosign/pull/1371)
* expose dafaults fulcio, rekor, oidc issuer urls (https://github.com/sigstore/cosign/pull/1368)
* Bump cloud.google.com/go/storage from 1.18.2 to 1.19.0 (https://github.com/sigstore/cosign/pull/1365)
* organize, update select deps (https://github.com/sigstore/cosign/pull/1358)
* Bump go-containerregistry to pick up ACR keychain fix (https://github.com/sigstore/cosign/pull/1357)
* Bump github.com/go-openapi/runtime from 0.21.0 to 0.21.1 (https://github.com/sigstore/cosign/pull/1352)
* sync go modules (https://github.com/sigstore/cosign/pull/1353)

## Contributors

* Batuhan Apaydın (@developer-guy)
* Carlos Tadeu Panato Junior (@cpanato)
* Dan Lorenc (@dlorenc)
* Jake Sanders (@dekkagaijin)
* Jason Hall (@imjasonh)
* Mark Lodato (@MarkLodato)
* Rémy Greinhofer (@rgreinho)

# v1.5.0

## Highlights

* enable sbom generation when releasing (https://github.com/sigstore/cosign/pull/1261)
* feat: log error to stderr (https://github.com/sigstore/cosign/pull/1260)
* feat: support attach attestation (https://github.com/sigstore/cosign/pull/1253)
* feat: resolve --cert from URL (https://github.com/sigstore/cosign/pull/1245)
* feat: generate/upload sbom for cosign projects (https://github.com/sigstore/cosign/pull/1237)
* feat: vuln attest support (https://github.com/sigstore/cosign/pull/1168)
* feat: add ambient credential detection with spiffe/spire (https://github.com/sigstore/cosign/pull/1220)
* feat: generate/upload sbom for cosign projects (https://github.com/sigstore/cosign/pull/1236)
* feat: implement cosign download attestation (https://github.com/sigstore/cosign/pull/1216)

## Enhancements

* Don't use k8schain, statically link cloud cred helpers in cosign (https://github.com/sigstore/cosign/pull/1279)
* Export function to verify individual signature (https://github.com/sigstore/cosign/pull/1334)
* Add suffix with digest to signature file output for recursive signing (https://github.com/sigstore/cosign/pull/1267)
* Take OIDC client secret into account (https://github.com/sigstore/cosign/pull/1310)
* Add --bundle flag to sign-blob and verify-blob (https://github.com/sigstore/cosign/pull/1306)
* Add flag to verify OIDC issuer in certificate (https://github.com/sigstore/cosign/pull/1308)
* add OSSF scorecard action (https://github.com/sigstore/cosign/pull/1318)
* Add TUF timestamp to attestation bundle (https://github.com/sigstore/cosign/pull/1316)
* Provide certificate flags to all verify commands (https://github.com/sigstore/cosign/pull/1305)
* Bundle TUF timestamp with signature on signing (https://github.com/sigstore/cosign/pull/1294)
* Add support for importing PKCShttps://github.com/sigstore/cosign/pull/8 private keys, and add validation (https://github.com/sigstore/cosign/pull/1300)
* add error message (https://github.com/sigstore/cosign/pull/1296)
* Move bundle out of `oci` and into `bundle` package (https://github.com/sigstore/cosign/pull/1295)
* Reorganize verify-blob code and add a unit test (https://github.com/sigstore/cosign/pull/1286)
* One-to-one mapping of invocation to scan result (https://github.com/sigstore/cosign/pull/1268)
* refactor common utilities (https://github.com/sigstore/cosign/pull/1266)
* Importing RSA and EC keypairs (https://github.com/sigstore/cosign/pull/1050)
* Refactor the tuf client code. (https://github.com/sigstore/cosign/pull/1252)
* Moved certificate output before checking for upload during signing (https://github.com/sigstore/cosign/pull/1255)
* Remove remaining ioutil usage (https://github.com/sigstore/cosign/pull/1256)
* Update the embedded TUF metadata. (https://github.com/sigstore/cosign/pull/1251)
* Add support for other public key types for SCT verification, allow override for testing. (https://github.com/sigstore/cosign/pull/1241)
* Log the proper remote repo for the signatures on verify (https://github.com/sigstore/cosign/pull/1243)
* Do not require multiple Fulcio certs in the TUF root (https://github.com/sigstore/cosign/pull/1230)
* clean up references to 'keyless' in `ephemeral.Signer` (https://github.com/sigstore/cosign/pull/1225)
* create `DSSEAttestor` interface, `payload.DSSEAttestor` implementation (https://github.com/sigstore/cosign/pull/1221)
* use `mutate.Signature` in the new `Signer`s (https://github.com/sigstore/cosign/pull/1213)
* create `mutate` functions for `oci.Signature` (https://github.com/sigstore/cosign/pull/1199)
* add a writeable `$HOME` for the `nonroot` cosigned user (https://github.com/sigstore/cosign/pull/1209)
* signing attestation should private key (https://github.com/sigstore/cosign/pull/1200)
* Remove the "upload" flag for "cosign initialize" (https://github.com/sigstore/cosign/pull/1201)
* create KeylessSigner (https://github.com/sigstore/cosign/pull/1189)

## Bug Fixes

* fix: cosign verify for vault (https://github.com/sigstore/cosign/pull/1328)
* fix missing goimports (https://github.com/sigstore/cosign/pull/1327)
* Fix TestSignBlobBundle (https://github.com/sigstore/cosign/pull/1320)
* Fix a couple bugs in cert verification for blobs (https://github.com/sigstore/cosign/pull/1287)
* Fix a few bugs in cosign initialize (https://github.com/sigstore/cosign/pull/1280)
* Fix the unit tests with expired TUF metadata. (https://github.com/sigstore/cosign/pull/1270)
* Fix output-file flag. (https://github.com/sigstore/cosign/pull/1264)
* fix: typo in the error message (https://github.com/sigstore/cosign/pull/1250)
* Fix semantic bugs in attestation verifification. (https://github.com/sigstore/cosign/pull/1249)
* Fix semantic bug in DSSE specification. (https://github.com/sigstore/cosign/pull/1248)

## Others

* Bump github.com/google/go-cmp from 0.5.6 to 0.5.7 (https://github.com/sigstore/cosign/pull/1343)
* Bump recommended Go development version in README (https://github.com/sigstore/cosign/pull/1340)
* Bump the snapshot and timestamp roles metadata from root signing. (https://github.com/sigstore/cosign/pull/1339)
* Bump github.com/spiffe/go-spiffe/v2 from 2.0.0-beta.10 to 2.0.0-beta.11 (https://github.com/sigstore/cosign/pull/1336)
* update go-github to v42 release (https://github.com/sigstore/cosign/pull/1335)
* install latest release for ko instead of head of main branch (https://github.com/sigstore/cosign/pull/1333)
* remove wrong settings in the gco auth for gh actions (https://github.com/sigstore/cosign/pull/1332)
* update gcp setup for the GH action (https://github.com/sigstore/cosign/pull/1330)
* update some dependencies (https://github.com/sigstore/cosign/pull/1326)
* Verify checksum of downloaded utilities during CI (https://github.com/sigstore/cosign/pull/1322)
* pin github actions by digest (https://github.com/sigstore/cosign/pull/1319)
* Bump google.golang.org/api from 0.64.0 to 0.65.0 (https://github.com/sigstore/cosign/pull/1303)
* Bump cuelang.org/go from 0.4.0 to 0.4.1 (https://github.com/sigstore/cosign/pull/1302)
* Bump github.com/xanzy/go-gitlab from 0.54.2 to 0.54.3 (https://github.com/sigstore/cosign/pull/1292)
* update import documentation (https://github.com/sigstore/cosign/pull/1290)
* update release image to use go 1.17.6 (https://github.com/sigstore/cosign/pull/1284)
* Bump google.golang.org/api. (https://github.com/sigstore/cosign/pull/1283)
* Bump opa and go-gitlab. (https://github.com/sigstore/cosign/pull/1281)
* Update SBOM spec to indicate compat for syft (https://github.com/sigstore/cosign/pull/1278)
* Bump miekg/pkcs11 (https://github.com/sigstore/cosign/pull/1275)
* Update signature spec with timestamp annotation (https://github.com/sigstore/cosign/pull/1274)
* Pick up latest knative.dev/pkg, and k8s 0.22 libs (https://github.com/sigstore/cosign/pull/1269)
* Bump sigstore/sigstore. (https://github.com/sigstore/cosign/pull/1247)
* Spelling (https://github.com/sigstore/cosign/pull/1246)
* Use ${{github.repository}} placeholder in OIDC GitHub workflow (https://github.com/sigstore/cosign/pull/1244)
* update codeowners list with missing codeowners (https://github.com/sigstore/cosign/pull/1238)
* update build images for release and bump cosign in the release job (https://github.com/sigstore/cosign/pull/1234)
* update deps (https://github.com/sigstore/cosign/pull/1222)
* nit: add comments to `Signer` interface (https://github.com/sigstore/cosign/pull/1228)
* update google.golang.org/api from 0.62.0 to 0.63.0 (https://github.com/sigstore/cosign/pull/1214)
* update snapshot and timestamp (https://github.com/sigstore/cosign/pull/1211)
* Bump github.com/spf13/viper from 1.9.0 to 1.10.0 (https://github.com/sigstore/cosign/pull/1198)
* Bump the DSSE library and handle manual changes in the API. (https://github.com/sigstore/cosign/pull/1191)
* nit: drop every section title down a level (https://github.com/sigstore/cosign/pull/1188)

## Contributors

* Andrew Block (@sabre1041)
* Asra Ali (@asraa)
* Batuhan Apaydın (@developer-guy)
* Bob Callaway (@bobcallaway)
* Carlos Alexandro Becker (@caarlos0)
* Carlos Tadeu Panato Junior (@cpanato)
* Dan Lorenc (@dlorenc)
* Hayden Blauzvern (@haydentherapper)
* Hector Fernandez (@hectorj2f)
* Itxaka (@Itxaka)
* Ivan Wallis (@venafi-iw)
* Jake Sanders (@dekkagaijin)
* Jason Hall (@imjasonh)
* Josh Dolitsky (@jdolitsky)
* Josh Soref (@jsoref)
* Matt Moore (@mattmoor)
* Morten Linderud (@Foxboron)
* Priya Wadhwa (@priyawadhwa)
* Radoslav Gerganov (@rgerganov)
* Rob Best (@ribbybibby)
* Sambhav Kothari (@samj1912)
* Ville Aikas (@vaikas)
* Zack Newman (@znewman01)

# v1.4.1

## Highlights

A whole buncha bugfixes!

## Enhancements

* Files created with `--output-signature` and `--output-certificate` now created with 0600 permissions (https://github.com/sigstore/cosign/pull/1151)
* Added `cosign verify-attestation --local-image` for verifying signed images with attestations from disk (https://github.com/sigstore/cosign/pull/1174)
* Added the ability to fetch the TUF root over HTTP with `cosign initialize --mirror` (https://github.com/sigstore/cosign/pull/1185)

## Bug Fixes

* Fixed saving and loading a signed image index to disk (https://github.com/sigstore/cosign/pull/1147)
* Fixed `sign-blob --output-certificate` writing an empty file (https://github.com/sigstore/cosign/pull/1149)
* Fixed assorted issues related to the initialization and use of Sigstore's TUF root of trust (https://github.com/sigstore/cosign/pull/1157)

## Contributors

* Carlos Alexandro Becker (@caarlos0)
* Carlos Panato (@cpanato)
* Hayden Blauzvern (@haydentherapper)
* Jake Sanders (@dekkagaijin)
* Matt Moore (@mattmoor)
* Priya Wadhwa (@priyawadhwa)
* Radoslav Gerganov (@rgerganov)

# v1.4.0

## Highlights

* BREAKING [COSIGN_EXPERIMENTAL]: This and future `cosign` releases will generate signatures that do not validate in older versions of `cosign`. This only applies to "keyless" experimental mode. To opt out of this behavior, use: `--fulcio-url=https://fulcio.sigstore.dev` when signing payloads (https://github.com/sigstore/cosign/pull/1127)
* BREAKING [cosign/pkg]: `SignedEntryTimestamp` is now of type `[]byte`. To get the previous behavior, call `strfmt.Base64(SignedEntryTimestamp)` (https://github.com/sigstore/cosign/pull/1083)
* `cosign-linux-pivkey-amd64` releases are now of the form `cosign-linux-pivkey-pkcs11key-amd64` (https://github.com/sigstore/cosign/pull/1052)
* Releases are now additionally signed using the keyless workflow (https://github.com/sigstore/cosign/pull/1073, https://github.com/sigstore/cosign/pull/1111)

## Enhancements

* Validate the whole attestation statement, not just the predicate (https://github.com/sigstore/cosign/pull/1035)
* Added the options to replace attestations using `cosign attest --replace` (https://github.com/sigstore/cosign/pull/1039)
* Added URI to `cosign verify-blob` output (https://github.com/sigstore/cosign/pull/1047)
* Signatures and certificates created by `cosign sign` and `cosign sign-blob` can be output to file using the `--output-signature` and `--output-certificate` flags, respectively (https://github.com/sigstore/cosign/pull/1016, https://github.com/sigstore/cosign/pull/1093, https://github.com/sigstore/cosign/pull/1066, https://github.com/sigstore/cosign/pull/1095)
* [cosign/pkg] Added the `pkg/oci/layout` package for storing signatures and attestations on disk (https://github.com/sigstore/cosign/pull/1040, https://github.com/sigstore/cosign/pull/1096)
* [cosign/pkg] Added `mutate` methods to attach `oci.File`s to `oci.Signed*` objects (https://github.com/sigstore/cosign/pull/1084)
* Added the `--signature-digest-algorithm` flag to `cosign verify`, allowing verification of container image signatures which were generated with a non-SHA256 signature algorithm (https://github.com/sigstore/cosign/pull/1071)
* Builds should now be reproducible (https://github.com/sigstore/cosign/pull/1053)
* Allows base64 files as `--cert` in `cosign verify-blob` (https://github.com/sigstore/cosign/pull/1088)
* Kubernetes secrets generated for version >= 1.21 clusters have the immutable bit set (https://github.com/sigstore/cosign/pull/1091)
* Added `cosign save` and `cosign load` commands to save and upload container images and associated signatures to disk (https://github.com/sigstore/cosign/pull/1094)
* `cosign sign` will no longer fail to sign private images in keyless mode without `--force` (https://github.com/sigstore/cosign/pull/1116)
* `cosign verify` now supports signatures stored in files and remote URLs with `--signature` (https://github.com/sigstore/cosign/pull/1068)
* `cosign verify` now supports certs stored in files (https://github.com/sigstore/cosign/pull/1095)
* Added support for `syft` format in `cosign attach sbom` (https://github.com/sigstore/cosign/pull/1137)

## Bug Fixes

* Fixed verification of Rekor bundles for InToto attestations (https://github.com/sigstore/cosign/pull/1030)
* Fixed a potential memory leak when signing and verifying with security keys (https://github.com/sigstore/cosign/pull/1113)

## Contributors

* Ashley Davis (@SgtCoDFish)
* Asra Ali (@asraa)
* Batuhan Apaydın (@developer-guy)
* Brandon Philips (@philips)
* Carlos Alexandro Becker (@caarlos0)
* Carlos Panato (@cpanato)
* Christian Rebischke (@shibumi)
* Dan Lorenc (@dlorenc)
* Erkan Zileli (@erkanzileli)
* Furkan Türkal (@Dentrax)
* garantir-km (@garantir-km)
* Jake Sanders (@dekkagaijin)
* jbpratt (@jbpratt)
* Matt Moore (@mattmoor)
* Mikey Strauss (@houdini91)
* Naveen Srinivasan (@naveensrinivasan)
* Priya Wadhwa (@priyawadhwa)
* Sambhav Kothari (@samj1912)

# v1.3.1

* BREAKING [cosign/pkg]: `cosign.Verify` has been removed in favor of explicit `cosign.VerifyImageSignatures` and `cosign.VerifyImageAttestations`
 (https://github.com/sigstore/cosign/pull/1026)

## Enhancements

* Add ability for verify-blob to find signing cert in transparency log (https://github.com/sigstore/cosign/pull/991)
* root policy: add optional issuer to maintainer keys (https://github.com/sigstore/cosign/pull/999)
* PKCS11 signing support (https://github.com/sigstore/cosign/pull/985)
* Included timeout option for uploading to Rekor (https://github.com/sigstore/cosign/pull/1001)

## Bug Fixes

* Bump sigstore/sigstore to pickup a fix for azure kms (https://github.com/sigstore/cosign/pull/1011 / https://github.com/sigstore/cosign/pull/1028)

## Contributors

* Asra Ali (@asraa)
* Batuhan Apaydın (@developer-guy)
* Carlos Panato (@cpanato)
* Dan Lorenc (@dlorenc)
* Dennis Leon (@DennisDenuto)
* Erkan Zileli (@erkanzileli)
* Furkan Türkal (@Dentrax)
* garantir-km (@garantir-km)
* Jake Sanders (@dekkagaijin)
* Naveen (@naveensrinivasan)

# v1.3.0

* BREAKING: `verify-manifest` is now `manifest verify` (https://github.com/sigstore/cosign/pull/712)
* BREAKING: `/pkg` has been heavily refactored. [Further refactoring work](https://github.com/sigstore/cosign/issues/844) will make its way into 1.4.0
* WARNING: The CLI now uses POSIX-style (double-dash `--flag`) for long-form flags. It will temporarily accept the single-dash `-flag` form with a warning, which will become an error in a future release (https://github.com/sigstore/cosign/pull/835)
* Added `sget` as part of Cosign's releases (https://github.com/sigstore/cosign/pull/752)
* The `copasetic` utility was unceremoniously [baleeted](https://www.youtube.com/watch?v=07h0ksKx5sM) (https://github.com/sigstore/cosign/pull/785)

## Enhancements

* Began reworking `/pkg` around new abstractions for signing, verification, and storage (https://github.com/sigstore/cosign/issues/666)
    * Notice: refactoring of `/pkg` will continue in the next minor release (1.4.0). Please leave feedback, especially if you've been experimenting with `cosign` as a library and found it lacking (https://github.com/sigstore/cosign/issues/844)
    * [GGCR-style libraries](https://github.com/google/go-containerregistry#philosophy) for interacting with images now exist under `pkg/oci` (https://github.com/sigstore/cosign/pull/770)
    * `pkg/cosign/remote.UploadSignature` API was been removed in favor of new `pkg/oci/remote` APIs (https://github.com/sigstore/cosign/pull/774)
    * The function signature of `cosign.Verify` was changed so that callers must be explicit about which signatures (or attestations) to verify. For matching signatures, see also `cosign.Verify{Signatures,Attestations}` (https://github.com/sigstore/cosign/pull/782)
    * Removed `cremote.UploadFile` in favor of `static.NewFile` and `remote.Write` (https://github.com/sigstore/cosign/pull/797)
* Innumerable other improvements to the codebase and automation ([Makin me look bad, @mattmoor](https://github.com/sigstore/cosign/commits?author=mattmoor))
* Migrated the CLI to `cobra` ([Welcome to the team, @n3wscott](https://github.com/sigstore/cosign/commits?author=n3wscott))
* Added the `--allow-insecure-registry` flag to disable TLS verification when interacting with insecure (e.g. self-signed) container registries (https://github.com/sigstore/cosign/pull/669)
* 🔒 `cosigned` now includes a mutating webhook that resolves image tags to digests (https://github.com/sigstore/cosign/pull/800)
* 🔒 The `cosigned` validating webhook now requires image digest references (https://github.com/sigstore/cosign/pull/799)
* The `cosigned` webhook now ignores resources that are being deleted (https://github.com/sigstore/cosign/pull/803)
* The `cosigned` webhook now supports resolving private images that are authenticated via `imagePullSecrets` (https://github.com/sigstore/cosign/pull/804)
* `manifest verify` now supports verifying images in all Kubernetes objects that fit within `PodSpec`, `PodSpecTemplate`, or `JobSpecTemplate`, including CRDs (https://github.com/sigstore/cosign/pull/697)
* Added shell auto-completion support (Clutch collab from @erkanzileli, @passcod, and @Dentrax! https://github.com/sigstore/cosign/pull/836)
* `cosign` has generated Markdown docs available in the `doc/` directory (https://github.com/sigstore/cosign/pull/839)
* Added support for verifying with secrets from a GitLab project (https://github.com/sigstore/cosign/pull/934)
* Added a `--k8s-keychain` option that enables cosign to support ambient registry credentials based on the "k8schain" library (https://github.com/sigstore/cosign/pull/972)
* CI (test) Images are now created for every architecture distroless ships on (currently: amd64, arm64, arm, s390x, ppc64le) (https://github.com/sigstore/cosign/pull/973)
* `attest`: replaced `--upload` flag with a `--no-upload` flag (https://github.com/sigstore/cosign/pull/979)

## Bug Fixes

* `cosigned` now verifies `CronJob` images (Terve, @vaikas https://github.com/sigstore/cosign/pull/809)
* Fixed the `verify` `--cert-email` option to actually work (Sweet as, @passcod https://github.com/sigstore/cosign/pull/821)
* `public-key -sk` no longer causes  `error: x509: unsupported public key type: *crypto.PublicKey` (https://github.com/sigstore/cosign/pull/864)
* Fixed interactive terminal support in Windows (https://github.com/sigstore/cosign/pull/871)
* The `-ct` flag is no longer ignored in `upload blob` (https://github.com/sigstore/cosign/pull/910)

## Contributors

* Aditya Sirish (@adityasaky)
* Asra Ali (@asraa)
* Axel Simon (@axelsimon)
* Batuhan Apaydın (@developer-guy)
* Brandon Mitchell (@sudo-bmitch)
* Carlos Panato (@cpanato)
* Chao Lin (@blackcat-lin)
* Dan Lorenc (@dlorenc)
* Dan Luhring (@luhring)
* Eng Zer Jun (@Juneezee)
* Erkan Zileli (@erkanzileli)
* Félix Saparelli (@passcod)
* Furkan Türkal (@Dentrax)
* Hector Fernandez (@hectorj2f)
* Ivan Font (@font)
* Jake Sanders (@dekkagaijin)
* Jason Hall (@imjasonh)
* Jim Bugwadia (@JimBugwadia)
* Joel Kamp (@mrjoelkamp)
* Luke Hinds (@lukehinds)
* Matt Moore (@mattmoor)
* Naveen (@naveensrinivasan)
* Olivier Gaumond (@oliviergaumond)
* Priya Wadhwa (@priyawadhwa)
* Radoslav Gerganov (@rgerganov)
* Ramkumar Chinchani (@rchincha)
* Rémy Greinhofer (@rgreinho)
* Scott Nichols (@n3wscott)
* Shubham Palriwala (@ShubhamPalriwala)
* Viacheslav Vasilyev (@avoidik)
* Ville Aikas (@vaikas)

# v1.2.0

## Enhancements
* BREAKING: move `verify-dockerfile` to `dockerfile verify` (https://github.com/sigstore/cosign/pull/662)
* Have the keyless `cosign sign` flow use a single 3LO. (https://github.com/sigstore/cosign/pull/665)
* Allow to `verify-blob` from urls (https://github.com/sigstore/cosign/pull/646)
* Support GCP environments without workload identity (GCB). (https://github.com/sigstore/cosign/pull/652)
* Switch the release cosign container to debug. (https://github.com/sigstore/cosign/pull/649)
* Add logic to detect and use ambient OIDC from exec envs. (https://github.com/sigstore/cosign/pull/644)
* Add `-cert-email` flag to provide the email expected from a fulcio cert to be valid (https://github.com/sigstore/cosign/pull/622)
* Add support for downloading signature from remote (https://github.com/sigstore/cosign/pull/629)
* Add sbom and attestations to triangulate (https://github.com/sigstore/cosign/pull/628)
* Add cosign attachment signing and verification (https://github.com/sigstore/cosign/pull/615)
* Embed CT log public key (https://github.com/sigstore/cosign/pull/607)
* Verify SCTs returned by fulcio (https://github.com/sigstore/cosign/pull/600)
* Add extra replacement variables and GCP's role identifier (https://github.com/sigstore/cosign/pull/597)
* Store attestations in the layer (payload) rather than the annotation. (https://github.com/sigstore/cosign/pull/579)
* Improve documentation about predicate type and change predicate type from provenance to slsaprovenance (https://github.com/sigstore/cosign/pull/583)
* Upgrade in-toto-golang to adapt SLSA Provenance (https://github.com/sigstore/cosign/pull/582)

## Bug Fixes
* Fix verify-dockerfile to allow lowercase FROM (https://github.com/sigstore/cosign/pull/643)
* Fix signing for the cosigned image. (https://github.com/sigstore/cosign/pull/634)
* Make sure generate-key-pair doesn't overwrite existing key-pair (https://github.com/sigstore/cosign/pull/623)
* helm/ci: update helm repo before installing the dependency (https://github.com/sigstore/cosign/pull/598)
* Set the correct predicate type/URI for each supported predicate type. (https://github.com/sigstore/cosign/pull/592)
* Warnings on admissionregistration version (https://github.com/sigstore/cosign/pull/581)
* Remove unnecessary COSIGN_PASSWORD (https://github.com/sigstore/cosign/pull/572)

## Contributors
* Batuhan Apaydın
* Ben Walding
* Carlos Alexandro Becker
* Carlos Tadeu Panato Junior
* Erkan Zileli
* Hector Fernandez
* Jake Sanders
* Jason Hall
* Matt Moore
* Michael Lieberman
* Naveen Srinivasan
* Pradeep Chhetri
* Sambhav Kothari
* dlorenc
* priyawadhwa


# v1.1.0

## Enhancements

* BREAKING: The `-attestation` flag has been renamed to `-predicate` in `attest` (https://github.com/sigstore/cosign/pull/500)
* Added `verify-manifest` command (https://github.com/sigstore/cosign/pull/490)
* Added the ability to specify and validate well-known attestation types in `attest` with the `-type` flag (https://github.com/sigstore/cosign/pull/504)
* Added `cosign init` command to setup the trusted local repository of SigStore's TUF root metadata (https://github.com/sigstore/cosign/pull/520)
* Added timestamps to Cosign's custom In-Toto predicate (https://github.com/sigstore/cosign/pull/533)
* `verify` now always verifies that the image exists (even when referenced by digest) before verification (https://github.com/sigstore/cosign/pull/543)

## Bug Fixes

* `verify-dockerfile` no longer fails on `FROM scratch` (https://github.com/sigstore/cosign/pull/509)
* Fixed reading from STDIN with `attach sbom` (https://github.com/sigstore/cosign/pull/517)
* Fixed broken documentation and implementation of `-output` for `verify` and `verify-attestation` (https://github.com/sigstore/cosign/pull/546)
* Fixed nil pointer error when calling `upload blob` without specifying `-f` (https://github.com/sigstore/cosign/pull/563)

## Contributors

* Adolfo García Veytia (@puerco)
* Anton Semjonov (@ansemjo)
* Asra Ali (@asraa)
* Batuhan Apaydın (@developer-guy)
* Carlos Panato (@cpanato)
* Dan Lorenc (@dlorenc)
* @gkovan
* Hector Fernandez (@hectorj2f)
* Jake Sanders (@dekkagaijin)
* Jim Bugwadia (@JimBugwadia)
* Jose Donizetti (@josedonizetti)
* Joshua Hansen (@joshes)
* Jason Hall (@imjasonh)
* Priya Wadhwa (@priyawadhwa)
* Russell Brown (@rjbrown57)
* Stephan Renatus (@srenatus)
* Li Yi (@denverdino)

# v1.0.0

## Enhancements

* BREAKING: The default HSM key slot is now "signature" instead of "authentication" (https://github.com/sigstore/cosign/pull/450)
* BREAKING: `--fulcio-server` is now `--fulcio-url` (https://github.com/sigstore/cosign/pull/471)
* Added `-cert` flag to `sign` to allow the explicit addition of a signature certificate (https://github.com/sigstore/cosign/pull/451)
* Added the `attest` command (https://github.com/sigstore/cosign/pull/458)
* Added numerous flags for specifying parameters when interacting with Rekor and Fulcio (https://github.com/sigstore/cosign/pull/462)
* `cosign` will now send its version string as part of the `user-agent` when interacting with a container registry (https://github.com/sigstore/cosign/pull/479)
* Files containing certificates for custom Fulcio endpoints can now be specified via the `COSIGN_ROOT` environment variable (https://github.com/sigstore/cosign/pull/477)

## Bug Fixes

* Fixed a situation where lower-case `as` would break `verify-dockerfile` (Complements to @Dentrax https://github.com/sigstore/cosign/pull/433)

## Contributors

* Appu Goundan (@loosebazooka)
* Batuhan Apaydın (@developer-guy)
* Carlos Panato (@cpanato)
* Dan Lorenc (@dlorenc)
* Furkan Türkal (@Dentrax)
* Hector Fernandez (@hectorj2f)
* Jake Sanders (@dekkagaijin)
* James Alseth (@jalseth)
* Jason Hall (@imjasonh)
* João Pereira (@joaodrp)
* Luke Hinds (@lukehinds)
* Tom Hennen (@TomHennen)

# v0.6.0

## Enhancements

* BREAKING: Moved `cosign upload-blob` to `cosign upload blob` (https://github.com/sigstore/cosign/pull/378)
* BREAKING: Moved `cosign upload` to `cosign attach signature` (https://github.com/sigstore/cosign/pull/378)
* BREAKING: Moved `cosign download` to `cosign download signature` (https://github.com/sigstore/cosign/pull/392)
* Added flags to specify slot, PIN, and touch policies for security keys (Thank you @ddz https://github.com/sigstore/cosign/pull/369)
* Added `cosign verify-dockerfile` command (https://github.com/sigstore/cosign/pull/395)
* Added SBOM support in `cosign attach` and `cosign download sbom` (https://github.com/sigstore/cosign/pull/387)
* Sign & verify images using Kubernetes secrets (A muchas muchas gracias to @developer-guy and @Dentrax https://github.com/sigstore/cosign/pull/398)
* Added support for AWS KMS (谢谢, @codysoyland https://github.com/sigstore/cosign/pull/426)
* Numerous enhancements to our build & release process, courtesy @cpanato

## Bug Fixes

* Verify entry timestamp signatures of fetched Tlog entries (https://github.com/sigstore/cosign/pull/371)

## Contributors

* Asra Ali (@asraa)
* Batuhan Apaydın (@developer-guy)
* Carlos Panato (@cpanato)
* Cody Soyland (@codysoyland)
* Dan Lorenc (@dlorenc)
* Dino A. Dai Zovi (@ddz)
* Furkan Türkal (@Dentrax)
* Jake Sanders (@dekkagaijin)
* Jason Hall (@imjasonh)
* Paris Zoumpouloglou (@zuBux)
* Priya Wadhwa (@priyawadhwa)
* Rémy Greinhofer (@rgreinho)
* Russell Brown (@rjbrown57)

# v0.5.0

## Enhancements

* Added `cosign copy` to easily move images and signatures between repositories (https://github.com/sigstore/cosign/pull/317)
* Added `-r` flag to `cosign sign` for recursively signing multi-arch images (https://github.com/sigstore/cosign/pull/320)
* Added `cosign clean` to delete signatures for an image (Thanks, @developer-guy! https://github.com/sigstore/cosign/pull/324)
* Added `-k8s` flag to `cosign generate-key-pair` to create a Kubernetes secret (Hell yeah, @priyawadhwa! https://github.com/sigstore/cosign/pull/345)

## Bug Fixes

* Fixed an issue with misdirected image signatures when `COSIGN_REPOSITORY` was used (https://github.com/sigstore/cosign/pull/323)

## Contributors

* Balazs Zachar (@Cajga)
* Batuhan Apaydın (@developer-guy)
* Dan Lorenc (@dlorenc)
* Furkan Turkal (@Dentrax)
* Jake Sanders (@dekkagaijin)
* Jon Johnson (@jonjohnsonjr)
* Priya Wadhwa (@priyawadhwa)

# v0.4.0

## Action Required

* Signatures created with `cosign` before v0.4.0 are not compatible with those created after
    * The signature image's manifest now uses OCI mediaTypes ([#300](https://github.com/sigstore/cosign/pull/300))
    * The signature image's tag is now terminated with `.sig` (instead of `.cosign`, [#287](https://github.com/sigstore/cosign/pull/287))

## Enhancements

* 🎉 Added support for "offline" verification of Rekor signatures 🎉 (ありがとう, priyawadhwa! [#285](https://github.com/sigstore/cosign/pull/285))
* Support for Hashicorp vault as a KMS provider has been added (Danke, RichiCoder1! [sigstore/sigstore #44](https://github.com/sigstore/sigstore/pull/44), [sigstore/sigstore #49](https://github.com/sigstore/sigstore/pull/44))

## Bug Fixes

* GCP KMS URIs now include the key version ([#45](https://github.com/sigstore/sigstore/pull/45))

## Contributors

* Christian Pearce (@pearcec)
* Dan Lorenc (@dlorenc)
* Jake Sanders (@dekkagaijin)
* Priya Wadhwa (@priyawadhwa)
* Richard Simpson (@RichiCoder1)
* Ross Timson (@rosstimson)

# v0.3.1

## Bug Fixes

* Fixed CI container image breakage introduced in v0.3.0
* Fixed lack of version information in release binaries

# v0.3.0

This is the third release of `cosign`!

We still expect many flags, commands, and formats to change going forward, but we're getting closer.
No backwards compatibility is promised or implied yet, though we are hoping to formalize this policy in the next release.
See [#254](https://github.com/sigstore/cosign/issues/254) for more info.

## Enhancements

* The `-output-file` flag supports writing output to a specific file
* The `-key` flag now supports `kms` references and URLs, the `kms` specific flag has been removed
* Yubikey/PIV hardware support is now included!
* Support for signing and verifying multiple images in one invocation

## Bug Fixes

* Bug fixes in KMS keypair generation
* Bug fixes in key type parsing

## Contributors

* Dan Lorenc
* Priya Wadhwa
* Ivan Font
* Dependabot!
* Mark Bestavros
* Jake Sanders
* Carlos Tadeu Panato Junior

# v0.2.0

This is the second release of `cosign`!

We still expect many flags, commands, and formats to change going forward, but we're getting closer.
No backwards compatibility is promised or implied.

## Enhancements

* The password for private keys can now be passed via the `COSIGN_PASSWORD`
* KMS keys can now be used to sign and verify blobs
* The `version` command can now be used to return the release version
* The `public-key` command can now be used to extract the public key from KMS or a private key
* The `COSIGN_REPOSITORY` environment variable can be used to store signatures in an alternate location
* Tons of new EXAMPLES in our help text

## Bug Fixes

* Improved error messages for command line flag verification
* TONS more unit and integration testing
* Too many others to count :)

## Contributors

We would love to thank the contributors:

* Dan Lorenc
* Priya Wadhwa
* Ahmet Alp Balkan
* Naveen Srinivasan
* Chris Norman
* Jon Johnson
* Kim Lewandowski
* Luke Hinds
* Bob Callaway
* Dan POP
* eminks
* Mark Bestavros
* Jake Sanders

# v0.1.0

This is the first release of `cosign`!

The main goal of this release is to release something we can start using to sign other releases of [sigstore](sigstore.dev) projects, including `cosign` itself.

We expect many flags, commands, and formats to change going forward.
No backwards compatibility is promised or implied.

## Enhancements

This release added a feature to `cosign` called `cosign`.
The `cosign` feature can be used to sign container images and blobs.
Detailed documentation can be found in the [README](README.md) and the [Detailed Usage](USAGE.md).

## Bug Fixes

There was no way to sign container images. Now there is!

## Contributors

We would love to thank the contributors:

* dlorenc
* priyawadhwa
* Ahmet Alp Balkan
* Ivan Font
* Jason Hall
* Chris Norman
* Jon Johnson
* Kim Lewandowski
* Luke Hinds
* Bob Callaway
