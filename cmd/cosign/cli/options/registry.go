// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package options

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	ecr "github.com/awslabs/amazon-ecr-credential-helper/ecr-login"
	"github.com/chrismellard/docker-credential-acr-env/pkg/credhelper"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/authn/github"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/google"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	alibabaacr "github.com/mozillazg/docker-credential-acr-helper/pkg/credhelper"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/spf13/cobra"
)

// Keychain is an alias of authn.Keychain to expose this configuration option to consumers of this lib
type Keychain = authn.Keychain

// RegistryOptions is the wrapper for the registry options.
type RegistryOptions struct {
	AllowInsecure      bool
	AllowHTTPRegistry  bool
	KubernetesKeychain bool
	RefOpts            ReferenceOptions
	Keychain           Keychain
	AuthConfig         authn.AuthConfig
	RegistryCACert     string
	RegistryClientCert string
	RegistryClientKey  string
	RegistryServerName string

	// RegistryClientOpts allows overriding the result of GetRegistryClientOpts.
	RegistryClientOpts []remote.Option
}

var _ Interface = (*RegistryOptions)(nil)

// AddFlags implements Interface
func (o *RegistryOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&o.AllowInsecure, "allow-insecure-registry", false,
		"whether to allow insecure connections to registries (e.g., with expired or self-signed TLS certificates). Don't use this for anything but testing")

	cmd.Flags().BoolVar(&o.AllowHTTPRegistry, "allow-http-registry", false,
		"whether to allow using HTTP protocol while connecting to registries. Don't use this for anything but testing")

	cmd.Flags().BoolVar(&o.KubernetesKeychain, "k8s-keychain", false,
		"whether to use the kubernetes keychain instead of the default keychain (supports workload identity).")

	cmd.Flags().StringVar(&o.AuthConfig.Username, "registry-username", "",
		"registry basic auth username")

	cmd.Flags().StringVar(&o.AuthConfig.Password, "registry-password", "",
		"registry basic auth password")

	cmd.Flags().StringVar(&o.AuthConfig.RegistryToken, "registry-token", "",
		"registry bearer auth token")

	cmd.Flags().StringVar(&o.RegistryCACert, "registry-cacert", "",
		"path to the X.509 CA certificate file in PEM format to be used for the connection to the registry")
	_ = cmd.MarkFlagFilename("registry-cacert", certificateExts...)

	cmd.Flags().StringVar(&o.RegistryClientCert, "registry-client-cert", "",
		"path to the X.509 certificate file in PEM format to be used for the connection to the registry")
	_ = cmd.MarkFlagFilename("registry-client-cert", certificateExts...)

	cmd.Flags().StringVar(&o.RegistryClientKey, "registry-client-key", "",
		"path to the X.509 private key file in PEM format to be used, together with the 'registry-client-cert' value, for the connection to the registry")
	_ = cmd.MarkFlagFilename("registry-client-key", privateKeyExts...)

	cmd.Flags().StringVar(&o.RegistryServerName, "registry-server-name", "",
		"SAN name to use as the 'ServerName' tls.Config field to verify the mTLS connection to the registry")

	o.RefOpts.AddFlags(cmd)
}

func (o *RegistryOptions) ClientOpts(ctx context.Context) ([]ociremote.Option, error) {
	opts := []ociremote.Option{ociremote.WithRemoteOptions(o.GetRegistryClientOpts(ctx)...)}
	if o.RefOpts.TagPrefix != "" {
		opts = append(opts, ociremote.WithPrefix(o.RefOpts.TagPrefix))
	}
	targetRepoOverride, err := ociremote.GetEnvTargetRepository()
	if err != nil {
		return nil, err
	}
	if (targetRepoOverride != name.Repository{}) {
		opts = append(opts, ociremote.WithTargetRepository(targetRepoOverride))
	}
	return opts, nil
}

func (o *RegistryOptions) NameOptions() []name.Option {
	var nameOpts []name.Option
	if o.AllowHTTPRegistry {
		nameOpts = append(nameOpts, name.Insecure)
	}
	return nameOpts
}

func (o *RegistryOptions) GetRegistryClientOpts(ctx context.Context) []remote.Option {
	if o.RegistryClientOpts != nil {
		ropts := o.RegistryClientOpts
		ropts = append(ropts, remote.WithContext(ctx))
		return ropts
	}

	opts := []remote.Option{
		remote.WithContext(ctx),
		remote.WithUserAgent(UserAgent()),
	}

	switch {
	case o.Keychain != nil:
		opts = append(opts, remote.WithAuthFromKeychain(o.Keychain))
	case o.KubernetesKeychain:
		kc := authn.NewMultiKeychain(
			authn.DefaultKeychain,
			google.Keychain,
			authn.NewKeychainFromHelper(ecr.NewECRHelper(ecr.WithLogger(io.Discard))),
			authn.NewKeychainFromHelper(credhelper.NewACRCredentialsHelper()),
			authn.NewKeychainFromHelper(alibabaacr.NewACRHelper().WithLoggerOut(io.Discard)),
			github.Keychain,
		)
		opts = append(opts, remote.WithAuthFromKeychain(kc))
	case o.AuthConfig.Username != "" && o.AuthConfig.Password != "":
		opts = append(opts, remote.WithAuth(&authn.Basic{Username: o.AuthConfig.Username, Password: o.AuthConfig.Password}))
	case o.AuthConfig.RegistryToken != "":
		opts = append(opts, remote.WithAuth(&authn.Bearer{Token: o.AuthConfig.RegistryToken}))
	default:
		opts = append(opts, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	}

	tlsConfig, err := o.getTLSConfig()
	if err == nil {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = tlsConfig
		opts = append(opts, remote.WithTransport(tr))
	}

	// Reuse a remote.Pusher and a remote.Puller for all operations that use these opts.
	// This allows us to avoid re-authenticating for everying remote.Function we call,
	// which speeds things up a whole lot.
	pusher, err := remote.NewPusher(opts...)
	if err == nil {
		opts = append(opts, remote.Reuse(pusher))
	}
	puller, err := remote.NewPuller(opts...)
	if err == nil {
		opts = append(opts, remote.Reuse(puller))
	}

	return opts
}

type RegistryReferrersMode string

const (
	RegistryReferrersModeLegacy RegistryReferrersMode = "legacy"
	RegistryReferrersModeOCI11  RegistryReferrersMode = "oci-1-1"
)

func (e *RegistryReferrersMode) String() string {
	return string(*e)
}

func (e *RegistryReferrersMode) Set(v string) error {
	switch v {
	case "legacy":
		*e = RegistryReferrersMode(v)
		return nil
	case "oci-1-1":
		if !EnableExperimental() {
			return fmt.Errorf(`in order to use  mode "%s", you must set COSIGN_EXPERIMENTAL=1`, v)
		}
		*e = RegistryReferrersMode(v)
		return nil
	default:
		return errors.New(`must be one of "legacy", "oci-1-1"`)
	}
}

func (e *RegistryReferrersMode) Type() string {
	return "registryReferrersMode"
}

// RegistryExperimentalOptions is the wrapper for the registry experimental options.
type RegistryExperimentalOptions struct {
	RegistryReferrersMode RegistryReferrersMode
}

var _ Interface = (*RegistryExperimentalOptions)(nil)

// AddFlags implements Interface
func (o *RegistryExperimentalOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().Var(&o.RegistryReferrersMode, "registry-referrers-mode",
		"mode for fetching references from the registry. allowed: legacy, oci-1-1")
}

func (o *RegistryOptions) getTLSConfig() (*tls.Config, error) {
	var tlsConfig tls.Config

	if o.RegistryCACert != "" {
		f, err := os.Open(o.RegistryCACert)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		caCertBytes, err := io.ReadAll(f)
		if err != nil {
			return nil, fmt.Errorf("unable to read CA certs from %s: %w", o.RegistryCACert, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCertBytes) {
			return nil, fmt.Errorf("no valid CA certs found in %s", o.RegistryCACert)
		}
		tlsConfig.RootCAs = pool
	}

	if o.RegistryClientCert != "" && o.RegistryClientKey != "" {
		cert, err := tls.LoadX509KeyPair(o.RegistryClientCert, o.RegistryClientKey)
		if err != nil {
			return nil, fmt.Errorf("unable to read client certs from cert %s, key %s: %w",
				o.RegistryClientCert, o.RegistryClientKey, err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	if o.RegistryServerName != "" {
		tlsConfig.ServerName = o.RegistryServerName
	}

	tlsConfig.InsecureSkipVerify = o.AllowInsecure // #nosec G402

	return &tlsConfig, nil
}
