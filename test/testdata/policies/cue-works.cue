import "time"

before: time.Parse(time.RFC3339, "2049-10-09T17:10:27Z")

// The predicateType field must match this string
predicateType: "cosign.sigstore.dev/attestation/v1"

// The predicate must match the following constraints.
predicate: {
    Timestamp: <before
}
