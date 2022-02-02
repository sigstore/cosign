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

package oidc

import (
	"context"

	"golang.org/x/oauth2"
)

// *NOTE* Most if not all of this should live in `sigstore/sigstore`

// IDToken is an OpenID ID token.
type IDToken struct { // OR use https://pkg.go.dev/github.com/coreos/go-oidc#IDToken (or something) instead?
	// our own impl of https://openid.net/specs/openid-connect-core-1_0.html#IDToken
}

func (t *IDToken) JWTEncode() string {
	return "TODO"
}

func JWTDecodeIDToken(rawIDToken string) (*IDToken, error) {
	return &IDToken{}, nil
}

// Provider describes an OpenID Provider.
type Provider interface {
	// GetIDToken returns an *IDToken
	GetIDToken(context.Context) (*IDToken, error)
}

// PotempkinProvider is a make-believe `Provider` implementation to throw rocks at.
// There should be one for each OAuth flow type (https://connect2id.com/learn/openid-connect#auth-request) we want to support.
type PotempkinProvider struct {
	oauthConfig oauth2.Config // token endpoints, client_id, client_secret, etc.
}

// GetIDToken implements Provider
func (p *PotempkinProvider) GetIDToken(context.Context) (*IDToken, error) {
	// TODO
	return &IDToken{}, nil
}
