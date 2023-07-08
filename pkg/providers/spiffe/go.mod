module github.com/sigstore/cosign/v2/pkg/providers/spiffe

go 1.20

replace github.com/sigstore/cosign/v2 => ../../../

require (
	github.com/sigstore/cosign/v2 v2.0.0-00010101000000-000000000000
	github.com/spiffe/go-spiffe/v2 v2.1.6
)

require (
	github.com/Microsoft/go-winio v0.6.1 // indirect
	github.com/go-jose/go-jose/v3 v3.0.0 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/zeebo/errs v1.3.0 // indirect
	golang.org/x/crypto v0.10.0 // indirect
	golang.org/x/mod v0.11.0 // indirect
	golang.org/x/net v0.11.0 // indirect
	golang.org/x/sys v0.9.0 // indirect
	golang.org/x/text v0.10.0 // indirect
	golang.org/x/tools v0.8.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20230530153820-e85fd2cbaebc // indirect
	google.golang.org/grpc v1.56.1 // indirect
	google.golang.org/protobuf v1.31.0 // indirect
)
