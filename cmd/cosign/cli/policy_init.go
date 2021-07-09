//
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

package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/generated/client/operations"
	"github.com/sigstore/sigstore/pkg/httpclients"
	"github.com/sigstore/sigstore/pkg/oauthflow"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/tlog"
	"github.com/spf13/viper"
	"io/ioutil"
	"net/http"
	"net/mail"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/peterbourgon/ff/v3/ffcli"
)

type MainPolicyStruct struct {
	BodyStruct   BodyStruct `json:"body"`
	SignedStruct SignedStruct     `json:"signed"`
}

type BodyStruct struct {
	Maintainers       []string  `json:"maintainers"`
	RegistryNamespace string    `json:"registry_namespace"`
	Threshold         int       `json:"threshold"`
	Expires           time.Time `json:"expires"`
}

type SignedStruct struct {
	Email      string `json:"email"`
	FulcioCert string `json:"fuclio_cert"`
	Signature  string `json:"signature"`
}

type Signed []*SignedStruct

func validEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

func PolicyInit() *ffcli.Command {
	var (
		flagset = flag.NewFlagSet("cosign policy-init", flag.ExitOnError)

		nameSpace   = flagset.String("ns", "", "The registry namespace")
		mainTainers = flagset.String("maintainers", "", "Comma separated list of maintainers")
		threshHold  = flagset.Int("threshold", 2, "Threshold")
		outFile  = flagset.String("out", "root.json", "Output policy locally")
	)

	return &ffcli.Command{
		Name:       "policy-init",
		ShortUsage: "generate a new keyless policy",
		ShortHelp:  "policy-init is used to generate a root.json policy for keyless signing delegation",
		LongHelp: `policy-init is used to generate a root.json policy
for keyless signing delegation. This is used to establish a policy for a registry namespace,
a signing threshold and a list of maintainers who can sign over the body section.

EXAMPLES
  # extract public key from private key to a specified out file.
  cosign policy-init -ns <project_namespace> --maintainers {email_addresses} --threshold <int> --expires <int>(days)`,
		FlagSet: flagset,
		Exec: func(ctx context.Context, args []string) error {

			var emailList []string

			// Process the list of maintainers by
			// 1. Ensure each entry is a correctly formatted email address
			// 2. If 1 is true, then remove surplus whitespace (caused by gaps between commas)
			emails := strings.Split(*mainTainers, ",")
			for _, email := range emails {
				if !validEmail(email) {
					panic(fmt.Sprintf("Invalid email format: %s", email))
				} else {
					emailList = append(emailList, email)
					// strip out whitespace if there is any
					for i := range emailList {
						emailList[i] = strings.TrimSpace(emailList[i])
					}
				}
			}

			// The body constitutes the main body section of the policy
			// These kv's contain security guarantees
			body := BodyStruct{
				Maintainers:       emailList,
				RegistryNamespace: *nameSpace,
				Threshold:         *threshHold,
				Expires:           time.Now(),
			}

			bodyByte, err := json.Marshal(body)
			if err != nil {
				return errors.Wrapf(err, "failed to marshal policy body json")
			}



			// Retrieve idToken from oidc provider re"
			idToken, err := oauthflow.OIDConnect(
				"https://oauth2.sigstore.dev/auth",
				"sigstore",
				"",
				oauthflow.DefaultIDTokenGetter,
			)
			if err != nil {
				return err
			}
			fmt.Println("\nReceived OpenID Scope retrieved for account:", idToken.Subject)

			signer, _, err := signature.NewDefaultECDSASignerVerifier()
			if err != nil {
				return err
			}

			pub, err := signer.PublicKey()
			if err != nil {
				return err
			}
			pubBytes, err := cryptoutils.MarshalPublicKeyToDER(pub)
			if err != nil {
				return err
			}

			proof, err := signer.SignMessage(strings.NewReader(idToken.Subject))
			if err != nil {
				return err
			}

			certResp, err := httpclients.GetCert(idToken, proof, pubBytes, "http://127.0.0.1:5555")
			if err != nil {
				switch t := err.(type) {
				case *operations.SigningCertDefault:
					if t.Code() == http.StatusInternalServerError {
						return err
					}
				default:
					return err
				}
				os.Exit(1)
			}

			certs, err := cryptoutils.UnmarshalCertificatesFromPEM([]byte(certResp.Payload))
			if err != nil {
				return err
			} else if len(certs) == 0 {
				return errors.New("no certificates were found in response")
			}
			signingCert := certs[0]
			signingCertPEM, err := cryptoutils.MarshalCertificateToPEM(signingCert)
			if err != nil {
				return err
			}

			sig, err := signer.SignMessage(bytes.NewReader(bodyByte))
			if err != nil {
				panic(fmt.Sprintf("Error occurred while during artifact signing: %s", err))
			}

			sigb64 := base64.StdEncoding.EncodeToString(sig)
			certb64 := base64.StdEncoding.EncodeToString(signingCertPEM)

			// We signed over this as maintainers
			signed := SignedStruct{
				Signature: sigb64,
				FulcioCert: certb64,
				Email: idToken.Subject,

			}

			// Construct the complete policy
			policyJSON := MainPolicyStruct{
				BodyStruct:   body,
				SignedStruct: signed,
			}// Signed is empty on first initialization of the policy


			policyByteArray, err := json.MarshalIndent(policyJSON, "", "  ")
			if err != nil {
				return errors.Wrapf(err, "failed to marshal policy json")
			}
			//fmt.Println(string(policyByteArray))

			// Send to rekor
			fmt.Println("Sending policy to transparency log")
			tlogEntry, err := tlog.UploadToRekor(
				signingCertPEM,
				sig,
				"http://127.0.0.1:3000",
				bodyByte,
			)
			if err != nil {
				return err
			}
			fmt.Printf("Rekor entry successful. URL: http://127.0.0.1:3000%v\n", tlogEntry)

			if viper.IsSet("output") {
				err = ioutil.WriteFile(viper.GetString("output"), signingCertPEM, 0600)
				if err != nil {
					return err
				}
			}

			if *outFile != "" {
				err = ioutil.WriteFile(*outFile, policyByteArray, 0600)
				if err != nil {
					return errors.Wrapf(err, "error writing to root.json")
				}
			}
			return nil
		},
	}
}
