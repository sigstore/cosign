module github.com/sigstore/cosign

go 1.16

require (
	cloud.google.com/go/storage v1.18.2
	cuelang.org/go v0.4.0
	github.com/ThalesIgnite/crypto11 v1.2.5
	github.com/cyberphone/json-canonicalization v0.0.0-20210823021906-dc406ceaf94b
	github.com/go-openapi/runtime v0.21.0
	github.com/go-openapi/strfmt v0.21.1
	github.com/go-openapi/swag v0.19.15
	github.com/go-piv/piv-go v1.9.0
	github.com/google/certificate-transparency-go v1.1.2
	github.com/google/go-cmp v0.5.6
	github.com/google/go-containerregistry v0.7.1-0.20211118220127-abdc633f8305
	github.com/google/go-containerregistry/pkg/authn/k8schain v0.0.0-20211203164431-c75901cce627
	github.com/google/go-github/v39 v39.2.0
	github.com/google/trillian v1.4.0
	github.com/in-toto/in-toto-golang v0.4.0-prerelease
	github.com/manifoldco/promptui v0.9.0
	github.com/miekg/pkcs11 v1.0.3
	github.com/open-policy-agent/opa v0.35.0
	github.com/pkg/errors v0.9.1
	github.com/secure-systems-lab/go-securesystemslib v0.2.0
	github.com/sigstore/fulcio v0.1.2-0.20211207184413-f4746cc4ff3d
	github.com/sigstore/rekor v0.3.1-0.20211203233407-3278f72b78bd
	github.com/sigstore/sigstore v1.0.2-0.20211203233310-c8e7f70eab4e
	github.com/spf13/cobra v1.2.1
	github.com/spf13/viper v1.9.0
	github.com/stretchr/testify v1.7.0
	github.com/theupdateframework/go-tuf v0.0.0-20211203210025-7ded50136bf9
	github.com/xanzy/go-gitlab v0.52.2
	golang.org/x/oauth2 v0.0.0-20211104180415-d3ed0bb246c8
	golang.org/x/term v0.0.0-20210927222741-03fcf44c2211
	google.golang.org/api v0.61.0
	k8s.io/api v0.21.7
	k8s.io/apimachinery v0.21.7
	k8s.io/client-go v0.21.7
	k8s.io/utils v0.0.0-20211203121628-587287796c64
	knative.dev/pkg v0.0.0-20211203062937-d37811b71d6a
)

require (
	github.com/form3tech-oss/jwt-go v3.2.5+incompatible // indirect
	github.com/mattn/go-runewidth v0.0.13 // indirect
	github.com/prometheus/procfs v0.7.3 // indirect
	github.com/urfave/cli v1.22.5 // indirect
	go.opentelemetry.io/contrib v1.2.0 // indirect
	go.opentelemetry.io/proto/otlp v0.11.0 // indirect
	k8s.io/klog/v2 v2.30.0 // indirect
)
