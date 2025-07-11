// Copyright 2025 The Sigstore Authors.
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

package signingconfig

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	prototrustroot "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
)

type CreateCmd struct {
	FulcioSpecs       []string
	RekorSpecs        []string
	OIDCProviderSpecs []string
	TSASpecs          []string
	TSAConfig         string
	RekorConfig       string
	Out               string
}

func (c *CreateCmd) Exec(_ context.Context) error {
	if len(c.RekorSpecs) > 0 && c.RekorConfig == "" {
		return fmt.Errorf("--rekor-config must be provided when --rekor is specified")
	}
	if len(c.TSASpecs) > 0 && c.TSAConfig == "" {
		return fmt.Errorf("--tsa-config must be provided when --tsa is specified")
	}

	fulcioServices := make([]root.Service, 0, len(c.FulcioSpecs))
	rekorServices := make([]root.Service, 0, len(c.RekorSpecs))
	oidcProviders := make([]root.Service, 0, len(c.OIDCProviderSpecs))
	tsaServices := make([]root.Service, 0, len(c.TSASpecs))

	rekorConfig, err := parseServiceConfig(c.RekorConfig)
	if err != nil {
		return fmt.Errorf("parsing rekor-config: %w", err)
	}

	tsaConfig, err := parseServiceConfig(c.TSAConfig)
	if err != nil {
		return fmt.Errorf("parsing tsa-config: %w", err)
	}

	for _, spec := range c.FulcioSpecs {
		svc, err := parseService(spec)
		if err != nil {
			return fmt.Errorf("parsing fulcio spec: %w", err)
		}
		fulcioServices = append(fulcioServices, svc)
	}

	for _, spec := range c.RekorSpecs {
		svc, err := parseService(spec)
		if err != nil {
			return fmt.Errorf("parsing rekor spec: %w", err)
		}
		rekorServices = append(rekorServices, svc)
	}

	for _, spec := range c.OIDCProviderSpecs {
		svc, err := parseService(spec)
		if err != nil {
			return fmt.Errorf("parsing oidc-provider spec: %w", err)
		}
		oidcProviders = append(oidcProviders, svc)
	}

	for _, spec := range c.TSASpecs {
		svc, err := parseService(spec)
		if err != nil {
			return fmt.Errorf("parsing tsa spec: %w", err)
		}
		tsaServices = append(tsaServices, svc)
	}

	signingConfig, err := root.NewSigningConfig(
		root.SigningConfigMediaType02,
		fulcioServices,
		oidcProviders,
		rekorServices,
		rekorConfig,
		tsaServices,
		tsaConfig,
	)
	if err != nil {
		return fmt.Errorf("creating signing config: %w", err)
	}

	scBytes, err := signingConfig.MarshalJSON()
	if err != nil {
		return err
	}

	if c.Out != "" {
		err = os.WriteFile(c.Out, scBytes, 0600)
		if err != nil {
			return err
		}
	} else {
		fmt.Println(string(scBytes))
	}

	return nil
}

func parseService(spec string) (root.Service, error) {
	kvs, err := parseKVs(spec)
	if err != nil {
		return root.Service{}, err
	}

	// Validate required keys
	requiredKeys := []string{"url", "api-version", "start-time", "operator"}
	for _, key := range requiredKeys {
		if val, ok := kvs[key]; !ok || val == "" {
			return root.Service{}, fmt.Errorf("missing required key '%s' in service spec", key)
		}
	}

	apiVersion, err := strconv.ParseUint(kvs["api-version"], 10, 32)
	if err != nil {
		return root.Service{}, fmt.Errorf("parsing api-version: %w", err)
	}

	startTime, err := time.Parse(time.RFC3339, kvs["start-time"])
	if err != nil {
		return root.Service{}, fmt.Errorf("parsing start-time: %w", err)
	}

	svc := root.Service{
		URL:                 kvs["url"],
		MajorAPIVersion:     uint32(apiVersion),
		Operator:            kvs["operator"],
		ValidityPeriodStart: startTime,
	}

	if et, ok := kvs["end-time"]; ok && et != "" {
		endTime, err := time.Parse(time.RFC3339, et)
		if err != nil {
			return root.Service{}, fmt.Errorf("parsing end-time: %w", err)
		}
		svc.ValidityPeriodEnd = endTime
	}
	return svc, nil
}

func parseKVs(spec string) (map[string]string, error) {
	kvs := make(map[string]string)
	pairs := strings.Split(spec, ",")
	for _, pair := range pairs {
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid key-value pair: %s", pair)
		}
		kvs[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}
	return kvs, nil
}

func parseServiceConfig(config string) (root.ServiceConfiguration, error) {
	if config == "" {
		return root.ServiceConfiguration{}, nil
	}
	parts := strings.SplitN(config, ":", 2)
	mode := strings.ToUpper(parts[0])
	var selector prototrustroot.ServiceSelector
	switch mode {
	case "ANY":
		selector = prototrustroot.ServiceSelector_ANY
		if len(parts) > 1 {
			return root.ServiceConfiguration{}, fmt.Errorf("mode %s does not accept a count", mode)
		}
		return root.ServiceConfiguration{Selector: selector}, nil
	case "ALL":
		selector = prototrustroot.ServiceSelector_ALL
		if len(parts) > 1 {
			return root.ServiceConfiguration{}, fmt.Errorf("mode %s does not accept a count", mode)
		}
		return root.ServiceConfiguration{Selector: selector}, nil
	case "EXACT":
		selector = prototrustroot.ServiceSelector_EXACT
		if len(parts) != 2 {
			return root.ServiceConfiguration{}, fmt.Errorf("mode EXACT requires a count, e.g. EXACT:2")
		}
		count, err := strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			return root.ServiceConfiguration{}, fmt.Errorf("invalid count for EXACT mode: %w", err)
		}
		return root.ServiceConfiguration{Selector: selector, Count: uint32(count)}, nil
	default:
		return root.ServiceConfiguration{}, fmt.Errorf("invalid service config mode: %s", mode)
	}
}
