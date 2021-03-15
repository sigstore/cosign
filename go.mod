module github.com/sigstore/cosign

go 1.15

require (
	cloud.google.com/go v0.79.0
	github.com/coreos/go-oidc v2.2.1+incompatible
	github.com/go-openapi/runtime v0.19.26
	github.com/go-openapi/strfmt v0.20.0
	github.com/go-openapi/swag v0.19.14
	github.com/google/go-cmp v0.5.5
	github.com/google/go-containerregistry v0.4.1-0.20210206001656-4d068fbcb51f
	github.com/google/trillian v1.3.13
	github.com/open-policy-agent/opa v0.26.0
	github.com/peterbourgon/ff/v3 v3.0.0
	github.com/pkg/errors v0.9.1
	github.com/pquerna/cachecontrol v0.0.0-20201205024021-ac21108117ac // indirect
	github.com/sigstore/fulcio v0.0.0-20210312120301-0b98f377a60b
	github.com/sigstore/rekor v0.1.1-0.20210228052401-f0b66bf3835c
	github.com/theupdateframework/go-tuf v0.0.0-20201230183259-aee6270feb55
	golang.org/x/oauth2 v0.0.0-20210220000619-9bb904979d93
	golang.org/x/term v0.0.0-20201210144234-2321bbc49cbf
	google.golang.org/genproto v0.0.0-20210310155132-4ce2db91004e
	google.golang.org/protobuf v1.25.0
)
