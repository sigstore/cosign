//
// Copyright 2022 The Sigstore Authors.
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

package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	webhookcip "github.com/sigstore/cosign/pkg/cosign/kubernetes/webhook/clusterimagepolicy"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"
)

const (
	// ImagePoliciesConfigName is the name of ConfigMap created by the
	// reconciler and consumed by the admission webhook.
	ImagePoliciesConfigName = "config-image-policies"
)

type ImagePolicyConfig struct {
	// This is the list of ImagePolicies that a admission controller uses
	// to make policy decisions.
	Policies map[string]webhookcip.ClusterImagePolicy
}

// NewImagePoliciesConfigFromMap creates an ImagePolicyConfig from the supplied
// Map
func NewImagePoliciesConfigFromMap(data map[string]string) (*ImagePolicyConfig, error) {
	ret := &ImagePolicyConfig{Policies: make(map[string]webhookcip.ClusterImagePolicy, len(data))}
	// Spin through the ConfigMap. Each key will point to resolved
	// ImagePatterns.
	for k, v := range data {
		// This is the example that we use to document / test the ConfigMap.
		if k == "_example" {
			continue
		}
		if v == "" {
			return nil, fmt.Errorf("configmap has an entry %q but no value", k)
		}
		clusterImagePolicy := &webhookcip.ClusterImagePolicy{}

		if err := parseEntry(v, clusterImagePolicy); err != nil {
			return nil, fmt.Errorf("failed to parse the entry %q : %q : %w", k, v, err)
		}
		ret.Policies[k] = *clusterImagePolicy
	}
	return ret, nil
}

// NewImagePoliciesConfigFromConfigMap creates a Features from the supplied ConfigMap
func NewImagePoliciesConfigFromConfigMap(config *corev1.ConfigMap) (*ImagePolicyConfig, error) {
	return NewImagePoliciesConfigFromMap(config.Data)
}

func parseEntry(entry string, out interface{}) error {
	j, err := yaml.YAMLToJSON([]byte(entry))
	if err != nil {
		return fmt.Errorf("config's value could not be converted to JSON: %w : %s", err, entry)
	}
	return json.Unmarshal(j, &out)
}

// GetMatchingPolicies returns all matching Policies and their Authorities that
// need to be matched for the given Image.
// Returned map contains the name of the CIP as the key, and an array of
// authorities from that Policy that must be validated against.
func (p *ImagePolicyConfig) GetMatchingPolicies(image string) (map[string][]webhookcip.Authority, error) {
	if p == nil {
		return nil, errors.New("config is nil")
	}

	var lastError error
	ret := map[string][]webhookcip.Authority{}

	// TODO(vaikas): this is very inefficient, we should have a better
	// way to go from image to Authorities, but just seeing if this is even
	// workable so fine for now.
	for k, v := range p.Policies {
		for _, pattern := range v.Images {
			if pattern.Glob != "" {
				if GlobMatch(image, pattern.Glob) {
					ret[k] = append(ret[k], v.Authorities...)
				}
			} else if pattern.Regex != "" {
				if regex, err := regexp.Compile(pattern.Regex); err != nil {
					lastError = err
				} else if regex.MatchString(image) {
					ret[k] = append(ret[k], v.Authorities...)
				}
			}
		}
	}
	return ret, lastError
}
