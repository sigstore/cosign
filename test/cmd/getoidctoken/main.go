// Copyright 2022 The Sigstore Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/kelseyhightower/envconfig"
)

type envConfig struct {
	FileName string `envconfig:"OIDC_FILE" default:"/var/run/sigstore/cosign/oidc-token" required:"true"`
}

func tokenWriter(filename string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		getToken(filename, w, req)
	}
}
func getToken(tokenFile string, w http.ResponseWriter, _ *http.Request) {
	content, err := ioutil.ReadFile(tokenFile)
	if err != nil {
		log.Print("failed to read token file", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_, err = fmt.Fprint(w, string(content))
	if err != nil {
		log.Print("failed to write token file to response", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func main() {
	var env envConfig
	if err := envconfig.Process("", &env); err != nil {
		log.Fatalf("failed to process env var: %s", err)
	}
	http.HandleFunc("/", tokenWriter(env.FileName))
	if err := http.ListenAndServe(":8080", nil); err != nil {
		panic(err)
	}
}
