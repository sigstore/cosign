module github.com/sigstore/cosign/v2/pkg/providers/buildkite

go 1.20

replace github.com/sigstore/cosign/v2 => ../../../

require (
	github.com/buildkite/agent/v3 v3.48.0
	github.com/sigstore/cosign/v2 v2.0.0-00010101000000-000000000000
)

require (
	github.com/google/go-querystring v1.1.0 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/pborman/uuid v1.2.1 // indirect
	golang.org/x/crypto v0.9.0 // indirect
	golang.org/x/exp v0.0.0-20230321023759-10a507213a29 // indirect
	golang.org/x/sys v0.8.0 // indirect
	golang.org/x/term v0.8.0 // indirect
)
