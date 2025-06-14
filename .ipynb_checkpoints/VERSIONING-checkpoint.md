# Cosign Versioning Policy

This is the versioning policy regarding the stability of Cosign, both the API and CLI.

**tl;dr (CLI):** semver for specific behaviors, but with deprecations.

**tl;dr (API):** no guarantees at all (for now).

Principles:

- Provide well-versioned, very reliable tools/libraries that people can write
  scripts/code against.
- Provide places for experimentation and rapid-development, not covered under
  versioning guarantees.
- Be explicit about what is and isn’t covered.
- Better to promise a weaker guarantee and stick to it consistently than to be
  vague about what is/isn’t covered and technically comply, or not comply at
  all.

## Cosign CLI

The Cosign CLI’s version numbers are of the form `MAJOR.MINOR.PATCH`, but it is
explicitly not covered by [semantic versioning][semver] guarantees. Instead, you
should interpret version numbers as follows:

**Major version increases.** These are "large changes." You should expect to
need to rewrite scripts after these. There are no compatibility guarantees about
the behavior or shape of the CLI. These should be infrequent and correspond to
big improvements in the user experience.

**Minor version increases.** These are "small changes." If you’ve been paying
attention to and fixing deprecation warnings (see
["Deprecation"](#deprecation)), your scripts should continue to work (provided
they only depend on explicitly guaranteed Cosign behavior; see "What's
covered?").

**Patch version increases.** These are "bug fix" releases only, and should
always be adopted..

[semver]: https://semver.org

### What's covered?

Only behavior explicitly listed here is covered (to counter [Hyrum's
Law][hyrums-law]).

* Any documented behavior (i.e., behavior described in the output of `cosign -h`).
  If the wording is ambiguous, the behavior may change as long as the
  corresponding documentation changes to make it less ambiguous.
* Output to standard output, *when described in the documentation*. Each command
  should describe its default output format (ideally with examples).
  * Any scripts should *only* rely on standard output.
  * Consumers using compliant parsers will continue to be able parse the output of Cosign.
  * New fields may be added, but fields will not be removed.
* Additional conventions documented in [CLI.md](CLI.md).

What’s *not* covered?

* Output to standard error is *not* covered and may change at any time.
* If the Sigstore API changes, the output of Cosign may change.
* Fixes to security bugs (for instance, something invalid used to pass
  verification, but now it does not). However, "security features" should not
  break backwards-compatibility.
* Any "unstable" commands.

Violations of this are generally considered bugs; we will issue patch releases
for each affected minor version. In some (rare) cases, an exception may be made
with the approval of the Cosign maintainers as long as the decision results in
an update to this versioning policy.

[hyrums-law]: https://www.hyrumslaw.com/

### Feature stability

It’s important to enable rapid iteration on the development of new Cosign
features while providing stability to users of more-mature features. As such,
the Cosign CLI will support the following release levels with corresponding
guarantees:

* **Experimental**: No guarantees. May change in a backwards-incompatible way or
  be removed at any time without warning.
* Generally available (**GA**): follows the guidelines in this document.

Users must explicitly indicate that they want to opt-in to experimental behavior
by setting the environment variable `COSIGN_EXPERIMENTAL=1`.

### Supported versions

**Full support.** We fully support only the latest release of the Cosign CLI.

**Security support.** We will backport security fixes to all major versions
released in the past year. We may backport security fixes, depending on
severity, to all minor versions released in the last year. We may choose to
backport security "features" as well.

### Deprecation

Any behavior may be deprecated at any time with sufficient warning. For GA
features, that period is 6 months from the Cosign release in which the
deprecation was first announced; the first subsequent Cosign release should
remove that feature. A new major version voids all deprecation timeline
guarantees, and any deprecated behaviors can be removed at that time.

Deprecation requires:

* When users invoke the deprecated behavior, print a deprecation message to
  standard error.
  * The message should look something like:
    ```
    WARNING: $BEHAVIOR is deprecated and will be removed in a Cosign release
    soon after $DEPRECATION_DATE (see $GITHUB_ISSUE_LINK). Instead, please
    $ALTERNATIVE.
    ```
  * If we can’t tell whether a user is using the deprecated behavior (for
    instance, if we’re going to remove a field), print the message every time.
  * There MAY be a way to turn off the message. In many cases, this will just be
    by using the alternative. Otherwise, we can consider adding a flag (which is
    now subject to a deprecation period of its own).
* A release note at the introduction of the deprecation, along with the removal
  of the behavior.
* Any documentation that refers to the deprecated behavior in the Cosign
  repository should have the same information as in the message.
  * Other documentation will be updated on a best-effort basis.

For a list of currently deprecated behavior, search the codebase (all deprecated
behavior will use a shared "deprecation" library and therefore be easy to find).

### Rationale/background

Currently, many folks assume that the Cosign CLI follows semantic versioning. We
have a bunch of breaking changes blocked on a 2.0 release. Even after that
point, there are a number of proposed breaking changes/overhauls proposed. But
there’s hesitancy to publish another major version. Further, semver doesn’t lend
itself to a regular deprecation train (marking things deprecated, then ripping
out after a fixed period of time); rather, in semver, you always have to wait
for a new major version, which batches together a bunch of proposed deprecated
behavior.

Approaches considered include:

* Follow semver. Bump major versions frequently (this is why Chrome is at
  version 107 and Firefox is at 106, and gcloud is at version 409). I think this
  is actually way more user-hostile; it effectively means "there are no
  compatibility guarantees."
* Follow semver. Avoid major version releases. I think that Sigstore and Cosign
  are developing too rapidly to commit to avoid breaking things. Further, this
  winds up preventing incremental improvements to the CLI in favor of huge
  changes. For instance, right now with the v2 work underway the codebase is in
  an awkward spot and would take a fair bit of work/branch management to push a
  minor version release; realistically, the next release will be v2 even if we
  have bug fixes we could push before then.

## API support for old Cosign versions

Starting with Cosign CLI v2, the Sigstore infrastructure should support old
Cosign versions for one year past release, and six months past the availability
of a suitable replacement. Any breakage here will be considered a bug and should
be rolled back or fixed.

We will run end-to-end tests for all prior supported minor versions.

## Cosign API

The Cosign API is versioned independently of the Cosign CLI. Version numbers are
`MAJOR.MINOR.PATCH`. For now, there are **no stability guarantees**:

* The library will undergo a serious refactor to make using it much
  safer/easier.
* Most callers (anybody not dealing with OCI registries/containers) will want
  [sigstore-go][] instead.
* At a future major version, the library will follow semantic versioning (and
  this policy will be updated).
* After that point, only code in pkg/ will be covered by semver; Cosign will
  follow semver strictly.
  * Functionality should be private (either language-private or in a "private"
    package like `internal/` or `cmd/`) by default, and exposing it publicly
    will be a deliberate choice.
  * In-development features will live under a new `pkg/experimental/` directory,
    which will not be covered by semver.
  * Updating a library is safer than updating a CLI tool, so we will bump major
    versions liberally (though not excessively).

### Rationale/background

We are not currently maintaining the Cosign API as if it’s a 1.0 library. There
are breaking changes all the time, and contributors don’t even seem to notice
(users might, but they haven’t complained much)! So effectively it's got no
versioning policy as-is; this just makes that official.

The only reason it’s marked 1.0 is because the CLI was marked 1.0; it certainly
isn’t ready for semver guarantees ([which Golang requires][go-semver]). Also, it
doesn’t make sense to tie the versions of the API and CLI to each other. If I
wanted to do a big refactor of the API that didn't affect the CLI, that might
require a major version bump even if the CLI was entirely unchanged.

Soon, [sigstore-go][] will be the default Golang API for Sigstore; this library
will have a well-thought-out API and be stable. After that point, we can
refactor Cosign to use it (see [Sigstore in Golang][sigstore-in-golang]) and
then clean up the Cosign API for those who need OCI support.

[go-semver]: https://go.dev/doc/modules/release-workflow#breaking
[sigstore-go]: https://github.com/sigstore/sigstore-go
[sigstore-in-golang]: https://docs.google.com/document/d/1aZfk1TlzcuaO0uz76M9D26-gAvoZLn0oCAKvkbuhcPM/edit
