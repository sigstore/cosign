module github.com/sigstore/cosign

go 1.16

require (
	cloud.google.com/go/storage v1.20.0
	cuelang.org/go v0.4.2
	github.com/ThalesIgnite/crypto11 v1.2.5
	github.com/awslabs/amazon-ecr-credential-helper/ecr-login v0.0.0-20211215200129-69c85dc22db6
	github.com/chrismellard/docker-credential-acr-env v0.0.0-20220119192733-fe33c00cee21
	github.com/cyberphone/json-canonicalization v0.0.0-20210823021906-dc406ceaf94b
	github.com/go-openapi/runtime v0.23.0
	github.com/go-openapi/strfmt v0.21.2
	github.com/go-openapi/swag v0.21.1
	github.com/go-piv/piv-go v1.9.0
	github.com/google/certificate-transparency-go v1.1.2
	github.com/google/go-cmp v0.5.7
	github.com/google/go-containerregistry v0.8.1-0.20220125170349-50dfc2733d10
	github.com/google/go-containerregistry/pkg/authn/k8schain v0.0.0-20220125170349-50dfc2733d10
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
	github.com/sigstore/sigstore v1.1.1-0.20220130134424-bae9b66b8442
	github.com/spf13/cobra v1.3.0
	github.com/spf13/viper v1.10.1
	github.com/spiffe/go-spiffe/v2 v2.0.0-beta.11
	github.com/stretchr/testify v1.7.0
	github.com/xanzy/go-gitlab v0.54.4
	github.com/theupdateframework/go-tuf v0.0.0-20220127213825-87caa18db2a6
	golang.org/x/oauth2 v0.0.0-20211104180415-d3ed0bb246c8
	golang.org/x/term v0.0.0-20210927222741-03fcf44c2211
	google.golang.org/api v0.68.0
	k8s.io/api v0.22.5
	k8s.io/apimachinery v0.22.5
	k8s.io/client-go v0.22.5
	k8s.io/utils v0.0.0-20211208161948-7d6a63dca704
	knative.dev/pkg v0.0.0-20220121092305-3ba5d72e310a
)

require (
	github.com/aws/aws-sdk-go-v2/config v1.13.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/ecr v1.14.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/ecrpublic v1.11.0 // indirect
	github.com/bytecodealliance/wasmtime-go v0.33.1 // indirect
	github.com/google/go-containerregistry/pkg/authn/kubernetes v0.0.0-20220125170349-50dfc2733d10 // indirect
	github.com/mattn/go-runewidth v0.0.13 // indirect
	github.com/prometheus/procfs v0.7.3 // indirect
	github.com/urfave/cli v1.22.5 // indirect
	go.opentelemetry.io/contrib v1.3.0 // indirect
	go.opentelemetry.io/proto/otlp v0.12.0 // indirect
	golang.org/x/crypto v0.0.0-20220126234351-aa10faf2a1f8 // indirect
	golang.org/x/net v0.0.0-20220121210141-e204ce36a2ba // indirect
	k8s.io/kube-openapi v0.0.0-20220124234850-424119656bbf // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.2.1 // indirect
)

replace github.com/theupdateframework/go-tuf => /home/asraa/git/go-tuf
