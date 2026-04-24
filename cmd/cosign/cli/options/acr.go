// Copyright 2026 The Sigstore Authors.
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
	"fmt"
	"os"
	"regexp"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/containers/azcontainerregistry"
)

var acrRE = regexp.MustCompile(`.*\.azurecr\.io|.*\.azurecr\.cn|.*\.azurecr\.de|.*\.azurecr\.us`)

// acrHelper implements authn.Helper for Azure Container Registry.
type acrHelper struct{}

func newACRHelper() *acrHelper {
	return &acrHelper{}
}

// Get returns ACR credentials for the given server URL, or ("", "", nil) if not an ACR endpoint.
func (h *acrHelper) Get(serverURL string) (string, string, error) {
	if !acrRE.MatchString(serverURL) {
		return "", "", nil
	}

	ctx := context.Background()

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return "", "", fmt.Errorf("acr: failed to create Azure credential: %w", err)
	}

	token, err := cred.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{"https://management.azure.com/.default"},
	})
	if err != nil {
		return "", "", fmt.Errorf("acr: failed to get AAD token: %w", err)
	}

	endpoint := fmt.Sprintf("https://%s", serverURL)
	authClient, err := azcontainerregistry.NewAuthenticationClient(endpoint, nil)
	if err != nil {
		return "", "", fmt.Errorf("acr: failed to create authentication client: %w", err)
	}

	tenantID := os.Getenv("AZURE_TENANT_ID")
	resp, err := authClient.ExchangeAADAccessTokenForACRRefreshToken(ctx,
		azcontainerregistry.PostContentSchemaGrantTypeAccessToken,
		serverURL,
		&azcontainerregistry.AuthenticationClientExchangeAADAccessTokenForACRRefreshTokenOptions{
			AccessToken: &token.Token,
			Tenant:      &tenantID,
		},
	)
	if err != nil {
		return "", "", fmt.Errorf("acr: failed to exchange AAD token for ACR refresh token: %w", err)
	}

	if resp.RefreshToken == nil {
		return "", "", fmt.Errorf("acr: received nil refresh token from ACR")
	}

	return "<token>", *resp.RefreshToken, nil
}
