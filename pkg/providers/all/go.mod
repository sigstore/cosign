// Deprecated
module github.com/sigstore/cosign/v2/pkg/providers/all

go 1.20

replace (
	github.com/sigstore/cosign/v2 => ../../../
	github.com/sigstore/cosign/v2/pkg/providers/buildkite => ../buildkite/
	github.com/sigstore/cosign/v2/pkg/providers/google => ../google/
	github.com/sigstore/cosign/v2/pkg/providers/spiffe => ../spiffe/
)

require (
	github.com/sigstore/cosign/v2 v2.0.0-00010101000000-000000000000
	github.com/sigstore/cosign/v2/pkg/providers/buildkite v0.0.0-00010101000000-000000000000
	github.com/sigstore/cosign/v2/pkg/providers/google v0.0.0-00010101000000-000000000000
	github.com/sigstore/cosign/v2/pkg/providers/spiffe v0.0.0-00010101000000-000000000000
)

require (
	cloud.google.com/go/compute v1.20.1 // indirect
	cloud.google.com/go/compute/metadata v0.2.3 // indirect
	github.com/Microsoft/go-winio v0.6.1 // indirect
	github.com/buildkite/agent/v3 v3.48.0 // indirect
	github.com/go-jose/go-jose/v3 v3.0.0 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/go-querystring v1.1.0 // indirect
	github.com/google/s2a-go v0.1.4 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.2.5 // indirect
	github.com/pborman/uuid v1.2.1 // indirect
	github.com/spiffe/go-spiffe/v2 v2.1.6 // indirect
	github.com/zeebo/errs v1.3.0 // indirect
	go.opencensus.io v0.24.0 // indirect
	golang.org/x/crypto v0.10.0 // indirect
	golang.org/x/exp v0.0.0-20230321023759-10a507213a29 // indirect
	golang.org/x/mod v0.11.0 // indirect
	golang.org/x/net v0.11.0 // indirect
	golang.org/x/oauth2 v0.9.0 // indirect
	golang.org/x/sys v0.9.0 // indirect
	golang.org/x/term v0.9.0 // indirect
	golang.org/x/text v0.10.0 // indirect
	golang.org/x/tools v0.8.0 // indirect
	google.golang.org/api v0.128.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20230530153820-e85fd2cbaebc // indirect
	google.golang.org/grpc v1.56.1 // indirect
	google.golang.org/protobuf v1.31.0 // indirect
)
