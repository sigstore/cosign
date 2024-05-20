Cosign E2E Tests
================

How to add end-to-end tests for cosign:

General-purpose tests
---------------------

If the test is only testing cosign itself or only needs access to Rekor and/or
Fulcio, add it to `e2e_test.go`. This test suite is run by the `e2e_test.sh`
script, which sets up Rekor, Fulcio, and an OIDC provider, so this can easily be
run in a developer environment with no additional setup steps.

In your tests, where cosign calls out to Fulcio or Rekor, make sure to set the
service URLs to the constants `rekorURL` or `fulcioURL`, which point to the
local instances of Rekor and Fulcio. Also have the test call the `setLocalEnv`
which downloads keys from the ephemeral Sigstore services and configures cosign
to trust them.

Environment-specific tests
--------------------------

If the test needs a more specific kind of environment, such as a KMS or an image
registry, create the test in its own file and designate a `go:build` tag for it.
In `e2e_test.go`, add a negation for that build tag.

In your tests, set the Rekor and Fulcio URLs to the contents of the environment
variables `REKOR_URL` and `FULCIO_URL`, if Rekor and Fulcio are needed for the
test.

Add a job for the new test in the ``e2e-test.yml`` GitHub workflow file. The job
should include the following:

- If the test needs access to Sigstore services, a step that calls the
  `sigstore/scaffolding/actions/setup` action
- Steps to do whatever other custom configuration the scenario needs
- A step to run the test with `go test -tags=e2e,<your tag> -v ./test/...`

To run these kinds of tests tests locally, you'll have to [setup
scaffolding](https://github.com/sigstore/scaffolding/blob/main/getting-started.md)
and do the other setup steps manually.

Dos
---

Add E2E tests to cover any interaction that cosign has with an external service,
such as Rekor, Fulcio, a TSA, etc, or for any case where it's not possible to
cover the functionality with a unit test.

Don'ts
------

- Do not add shell scripts that call the cosign binary directly unless the
  functionality under test is the CLI itself and absolutely cannot be tested any
  other way. As much as possible, tests should be runnable with `go test`.

- Do not allow the tests to call the production or staging instances of the
  Sigstore services, i.e. any `*.sigstore.dev` or `*.sigstage.dev` services.
  They should use the local CI instances to avoid spamming the real
  infrastructure.
