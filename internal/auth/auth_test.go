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

package auth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/sigstore/cosign/v2/pkg/providers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	// Generated from https://justtrustme.dev/token?sub=test-subject
	dummyJWT = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImFhOWE1YjA5LTExMzktNGU2YS1hNjMxLTA2ZTU3NDU4NzI0MSJ9.eyJleHAiOjE3NTM4MzY1NTIsImlhdCI6MTc1MzgzNDc1MiwiaXNzIjoiaHR0cHM6Ly9qdXN0dHJ1c3RtZS5kZXYiLCJzdWIiOiJ0ZXN0LXN1YmplY3QifQ.WWNGLWQsSDcz0cFlGbMfmLkGaMpiAsVfik2vAj_YPIXNG6jgkMmIF69TbrwH-qlSfKNNI1GTktxlufsQwOUiseVdqV7fOCdvPhQsozHye8JT-AgZ9wcH3DGcdp-5R5KOKlFNXHFcBjI9lS0KIelWoJLj8YzisOi0hWRdAwpJwuselV-d7IlcLZhJiZO3n-d15YB4fRMpjTr_aj--hdec7ywzmCQqKL3XdAjAmR99JExMKs_w25-6K7akjVSE1lljf8Wf9CBfOlwvWKxXPvIwzE0DC2yWS103yWfGHEf3UbKPlF34Xqo6beHTnf9uiO0HdWTaQp2e0eShsQDX9hpIeg"
)

func Test_idToken(t *testing.T) {
	td := t.TempDir()
	tokenFile := filepath.Join(td, "token.jwt")
	err := os.WriteFile(tokenFile, []byte(dummyJWT), 0600)
	require.NoError(t, err)

	nonExistentFile := filepath.Join(td, "nonexistent")

	tests := []struct {
		name    string
		s       string
		want    string
		wantErr bool
	}{
		{
			name: "empty string",
			s:    "",
			want: "",
		},
		{
			name: "valid jwt",
			s:    dummyJWT,
			want: dummyJWT,
		},
		{
			name:    "not a jwt or file",
			s:       "not-a-jwt",
			wantErr: true,
		},
		{
			name: "file path",
			s:    tokenFile,
			want: dummyJWT,
		},
		{
			name:    "non-existent file",
			s:       nonExistentFile,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := idToken(tt.s)
			if (err != nil) != tt.wantErr {
				t.Errorf("idToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("idToken() = %v, want %v", got, tt.want)
			}
		})
	}
}

type mockProvider struct {
	token string
	err   error
}

func (m *mockProvider) Enabled(_ context.Context) bool {
	return true
}

func (m *mockProvider) Provide(_ context.Context, _ string) (string, error) {
	return m.token, m.err
}

func TestReadIDToken(t *testing.T) {
	ctx := context.Background()
	td := t.TempDir()
	tokenFile := filepath.Join(td, "token.jwt")
	err := os.WriteFile(tokenFile, []byte(dummyJWT), 0600)
	require.NoError(t, err)

	providers.Register("mock-success", &mockProvider{token: "mock-token"})
	providers.Register("mock-fail", &mockProvider{err: errors.New("mock error")})

	tests := []struct {
		name             string
		tokOrPath        string
		disableProviders bool
		oidcProvider     string
		want             string
		wantErr          bool
	}{
		{
			name:      "raw token",
			tokOrPath: dummyJWT,
			want:      dummyJWT,
		},
		{
			name:      "token from file",
			tokOrPath: tokenFile,
			want:      dummyJWT,
		},
		{
			name:             "no token, providers disabled",
			tokOrPath:        "",
			disableProviders: true,
			want:             "",
		},
		{
			name:         "no token, specific provider success",
			tokOrPath:    "",
			oidcProvider: "mock-success",
			want:         "mock-token",
		},
		{
			name:         "no token, specific provider fail",
			tokOrPath:    "",
			oidcProvider: "mock-fail",
			wantErr:      true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ReadIDToken(ctx, tt.tokOrPath, tt.disableProviders, tt.oidcProvider)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReadIDToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ReadIDToken() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetOAuthFlow(t *testing.T) {
	tests := []struct {
		name     string
		authFlow string
		idToken  string
		want     string
	}{
		{
			name:     "auth flow set explicitly",
			authFlow: "client_credentials",
			want:     "client_credentials",
		},
		{
			name:    "id token set",
			idToken: dummyJWT,
			want:    "token",
		},
		// Other flows can't be easily tested due to lack of interactivity
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetOAuthFlow(context.Background(), tt.authFlow, tt.idToken, false)

			if err != nil {
				t.Errorf("GetOAuthFlow() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("GetOAuthFlow() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthenticateCaller(t *testing.T) {
	t.Run("token flow", func(t *testing.T) {
		subject, token, err := AuthenticateCaller("token", dummyJWT, "", "", "", "")
		require.NoError(t, err)
		assert.Equal(t, "test-subject", subject)
		assert.Equal(t, dummyJWT, token)
	})

	t.Run("unsupported flow", func(t *testing.T) {
		_, _, err := AuthenticateCaller("bad-flow", "", "", "", "", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported oauth flow")
	})
}
