import "time"

// This is after our scan happened
before: time.Parse(time.RFC3339, "2022-04-01T17:10:27Z")
after: time.Parse(time.RFC3339, "2022-03-09T17:10:27Z")

// The predicateType field must match this string
predicateType: "https://cosign.sigstore.dev/attestation/vuln/v1"

predicate: {
  invocation: {
    // This is the wrong invocation uri
    uri: "invocation.example.com/cosign-testing-invalid"
  }
  scanner: {
    // This is the wrong scanner uri
    uri: "fakescanner.example.com/cosign-testing-invalid"
  }
  metadata: {
    scanStartedOn: <before
    scanStartedOn: >after
    scanFinishedOn: <before
    scanFinishedOn: >after
  }
}
