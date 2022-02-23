module github.com/sigstore/cosign

go 1.16

require (
	cloud.google.com/go/storage v1.21.0
	cuelang.org/go v0.4.2
	github.com/ThalesIgnite/crypto11 v1.2.5
	github.com/awslabs/amazon-ecr-credential-helper/ecr-login v0.0.0-20220216180153-3d7835abdf40
	github.com/chrismellard/docker-credential-acr-env v0.0.0-20220119192733-fe33c00cee21
	github.com/cyberphone/json-canonicalization v0.0.0-20210823021906-dc406ceaf94b
	github.com/go-openapi/runtime v0.23.1
	github.com/go-openapi/strfmt v0.21.2
	github.com/go-openapi/swag v0.21.1
	github.com/go-piv/piv-go v1.9.0
	github.com/google/certificate-transparency-go v1.1.2
	github.com/google/go-cmp v0.5.7
	github.com/google/go-containerregistry v0.8.1-0.20220209165246-a44adc326839
	github.com/google/go-github/v42 v42.0.0
	github.com/google/trillian v1.4.0
	github.com/in-toto/in-toto-golang v0.3.4-0.20211211042327-af1f9fb822bf
	github.com/manifoldco/promptui v0.9.0
	github.com/miekg/pkcs11 v1.1.1
	github.com/open-policy-agent/opa v0.35.0
	github.com/pkg/errors v0.9.1
	github.com/secure-systems-lab/go-securesystemslib v0.3.0
	github.com/sigstore/fulcio v0.1.2-0.20220114150912-86a2036f9bc7
	github.com/sigstore/rekor v0.4.1-0.20220114213500-23f583409af3
	github.com/sigstore/sigstore v1.1.1-0.20220217212907-e48ca03a5ba7
	github.com/spf13/cobra v1.3.0
	github.com/spf13/viper v1.10.1
	github.com/spiffe/go-spiffe/v2 v2.0.0-beta.11
	github.com/stretchr/testify v1.7.0
	github.com/theupdateframework/go-tuf v0.0.0-20220211205608-f0c3294f63b9
	github.com/xanzy/go-gitlab v0.55.1
	golang.org/x/oauth2 v0.0.0-20211104180415-d3ed0bb246c8
	golang.org/x/term v0.0.0-20210927222741-03fcf44c2211
	google.golang.org/api v0.70.0
	k8s.io/api v0.23.3
	k8s.io/apimachinery v0.23.3
	k8s.io/client-go v0.23.3
	k8s.io/utils v0.0.0-20220127004650-9b3446523e65
	knative.dev/pkg v0.0.0-20220202132633-df430fa0dd96
	sigs.k8s.io/release-utils v0.4.1-0.20220207182343-6dadf2228617
)

require (
	github.com/armon/go-metrics v0.3.10
	github.com/armon/go-radix v1.0.0
	github.com/bytecodealliance/wasmtime-go v0.33.1 // indirect
	github.com/form3tech-oss/jwt-go v3.2.5+incompatible // indirect
	github.com/golang/snappy v0.0.4
	github.com/google/go-containerregistry/pkg/authn/k8schain v0.0.0-20220219142810-1571d7fdc46e
	github.com/hashicorp/errwrap v1.1.0
	github.com/hashicorp/go-hclog v1.1.0
	github.com/hashicorp/go-immutable-radix v1.3.1
	github.com/hashicorp/go-multierror v1.1.1
	github.com/hashicorp/go-plugin v1.4.3
	github.com/hashicorp/go-secure-stdlib/mlock v0.1.2
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.2
	github.com/hashicorp/go-sockaddr v1.0.2
	github.com/hashicorp/go-uuid v1.0.2
	github.com/hashicorp/go-version v1.4.0
	github.com/hashicorp/golang-lru v0.5.4
	github.com/hashicorp/hcl v1.0.0
	github.com/hashicorp/vault/sdk v0.3.0
	github.com/mattn/go-runewidth v0.0.13 // indirect
	github.com/mitchellh/copystructure v1.2.0
	github.com/mitchellh/go-testing-interface v1.14.1
	github.com/mitchellh/mapstructure v1.4.3
	github.com/pierrec/lz4 v2.6.1+incompatible
	github.com/prometheus/procfs v0.7.3 // indirect
	github.com/spf13/afero v1.8.0 // indirect
	github.com/urfave/cli v1.22.5 // indirect
	github.com/withfig/autocomplete-tools/packages/cobra v0.0.0-20220122124547-31d3821a6898
	go.opentelemetry.io/contrib v1.3.0 // indirect
	go.opentelemetry.io/proto/otlp v0.12.0 // indirect
	go.uber.org/atomic v1.9.0
	go.uber.org/zap v1.20.0
	golang.org/x/crypto v0.0.0-20220213190939-1e6e3497d506
	google.golang.org/protobuf v1.27.1
	k8s.io/code-generator v0.22.5
	k8s.io/kube-openapi v0.0.0-20220124234850-424119656bbf
	knative.dev/hack v0.0.0-20220118141833-9b2ed8471e30
)

// This is temporary to address conflicting versions of Kubernetes libs in knative and GGCR.
replace (
	k8s.io/api => k8s.io/api v0.22.5
	k8s.io/apimachinery => k8s.io/apimachinery v0.22.5
	k8s.io/client-go => k8s.io/client-go v0.22.5
)
