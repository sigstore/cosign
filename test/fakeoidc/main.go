//
// Copyright 2024 The Sigstore Authors.
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

// Mock OIDC server, based on https://github.com/sigstore/fulcio/blob/efec18aaed12d1f91eeaaba96e90f86170c2ada4/pkg/server/grpc_server_test.go#L2235
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

var (
	signer jose.Signer
	jwk    jose.JSONWebKey
)

type config struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

type customClaims struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

func init() {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	jwk = jose.JSONWebKey{
		Algorithm: string(jose.RS256),
		Key:       pk,
	}
	signer, err = jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       jwk.Key,
	}, nil)
	if err != nil {
		log.Fatal(err)
	}
}

func token(w http.ResponseWriter, r *http.Request) {
	log.Print("handling token")
	token, err := jwt.Signed(signer).Claims(jwt.Claims{
		Issuer:   fmt.Sprintf("http://%s", r.Host),
		IssuedAt: jwt.NewNumericDate(time.Now()),
		Expiry:   jwt.NewNumericDate(time.Now().Add(30 * time.Minute)),
		Subject:  "foo@bar.com",
		Audience: jwt.Audience{"sigstore"},
	}).Claims(customClaims{
		Email:         "foo@bar.com",
		EmailVerified: true,
	}).Serialize()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	w.Write([]byte(token))
}

func keys(w http.ResponseWriter, r *http.Request) {
	log.Print("handling keys")
	keys, err := json.Marshal(jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			jwk.Public(),
		},
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	w.Header().Add("Content-type", "application/json")
	w.Write(keys)
}

func wellKnown(w http.ResponseWriter, r *http.Request) {
	log.Print("handling discovery")
	issuer := fmt.Sprintf("http://%s", r.Host)
	cfg, err := json.Marshal(config{
		Issuer:  issuer,
		JWKSURI: issuer + "/keys",
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	w.Header().Add("Content-type", "application/json")
	w.Write(cfg)
}

func main() {
	http.HandleFunc("/token", token)
	http.HandleFunc("/keys", keys)
	http.HandleFunc("/.well-known/openid-configuration", wellKnown)
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}
