import "time"

before: time.Parse(time.RFC3339, "2022-04-15T17:10:27Z")
after: time.Parse(time.RFC3339, "2022-03-09T17:10:27Z")

// The predicateType field must match this string
predicateType: "https://cosign.sigstore.dev/attestation/vuln/v1"

predicate: {
  invocation: {
    uri: "invocation.example.com/cosign-testing"
  }
  scanner: {
    uri: "fakescanner.example.com/cosign-testing"
  }
  metadata: {
    scanStartedOn: <before
    scanStartedOn: >after
    scanFinishedOn: <before
    scanFinishedOn: >after
  }
}
