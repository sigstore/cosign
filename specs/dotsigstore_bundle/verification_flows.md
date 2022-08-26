# Purpose

Enumerate the cosign verification use-cases with various keyed/keyless
modes and TUF configurations.

| Description | Keytype | Rekor entry | Root CA | Key status | Verification |
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
