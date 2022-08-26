# Purpose

Enumerate the cosign verification use-cases with various keyed/keyless
modes and TUF configurations. Scneraios with different Rekor/Fulcio
instances (e.g. local, staging, corporate etc) are not explicitly
listed, as via the correct command line parameter, the client should
be able to figure out which keys to load in the TUF repository.

| Case | Keytype | Rekor entry | Root CA | Key status | Verification passes |
|-------------|---------|-------------|---------|------------|--------------|
| #1   | Keyless | Yes         | Fulcio  | Valid      | :white_check_mark:  |
| #2   | User provided | No | N/A | N/A: Verifier provides a set of accepted keys | :white_check_mark: |
| #2.1 | User provided | Yes | N/A | Not known by verifier | :no_entry_sign: |
| #3.1 | Keyless | Yes | Fulcio | Rekor key valid during signature generation, but new Rekor key published since then. | :white_check_mark: |
| #3.2 | Keyless | Yes | Fulcio | Rekor SET signed with an old key. (i.e the Rekor entry is forged) | :no_entry_sign: |
| #3.3 | Keyless | Yes | Fulcio | Current Rekor key (e.g. 5.root.json) but offline client only have 3.root.json; that is, an older Rekor key | :no_entry_sign: |
| #3.4 | Keyless | Yes | Fulcio | Fulcio intermediate certificate valid during signing, but now rotated. | :white_check_mark: |
| #3.5 | Keyless | yes | Fulcio | Fulcio intermediate certificate expired during signing. | :no_entry_sign: |
| #4.1 | User provided cert | Yes | User provided | Verifier have root CA | :white_check_mark: |
| #4.2 | User provided cert | Yes | User provided | Verifier does not know root CA | :no_entry_sign: |
| #5   | Keyless | Yes | Fulcio | Valid. SET in the Rekor entry does not match payload. | :no_entry_sign: |

## Notes on verification

The `cosign verify-blob` command already accepts a set of parameters
that are related to this extended bundle proposal. Some proposed
changes to the parameters:

| Command | Description |
|---------|-------------|
| `--bundle` | Old bundle format, not used for this bundle type. |
| `--sigstore-bundle` | Path to `file.sigstore` bundle. |
| `--certificate` | Specifies the cert to use, must not be used with `--sigstore-bundle` as cert is provided in the bundle. Expected to be verified against Fulcio root CA, unless `--certificate-chain` is provided.  |
| `--certificate-chain` | Path to a list of CA certificates. Can be used if another CA than Fulcio is used. |
| `--key` | Must be provided if user provided key is used. |
| `--rekor-url` | Not strictly related to this, but used to specify Rekor URL so the correct key can be located in the TUF metadata in case of a multi-TUF-root scenario. |
| `--fulcio-url` | Not strictly related to this, but used to specify Fulcio URL so the correct key can be located in the TUF metadata in case of a multi-TUF-root scenario. |
| `--signature` | Must not be used together with `--sigstore-bundle` as signature is located in the bundle file. |
