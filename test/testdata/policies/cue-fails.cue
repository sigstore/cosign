import "time"

before: time.Parse(time.RFC3339, "2049-10-09T17:10:27Z")

// Test with invalid predicate type. It should be this, so change it
//predicateType: "cosign.sigstore.dev/attestation/v1"
predicateType: "cosignnotreally.sigstore.dev/attestation/v1"

// The predicate must match the following constraints.
predicate: {
    Timestamp: <before
}
