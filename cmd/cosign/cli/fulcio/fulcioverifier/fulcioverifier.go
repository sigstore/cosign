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

package fulcioverifier

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/pkg/errors"

	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio/fulcioverifier/ctl"
	fulciopb "github.com/sigstore/fulcio/pkg/generated/protobuf"
)

func NewSigner(ctx context.Context, idToken, oidcIssuer, oidcClientID, oidcClientSecret, oidcRedirectURL string, fClient fulciopb.CAClient) (*fulcio.Signer, error) {
	fs, err := fulcio.NewSigner(ctx, idToken, oidcIssuer, oidcClientID, oidcClientSecret, oidcRedirectURL, fClient)
	if err != nil {
		return nil, err
	}

	// verify the sct
	if err := ctl.VerifySCT(ctx, []byte(fs.Cert), []byte(strings.Join(fs.Chain, "\n")), fs.SCT); err != nil {
		return nil, errors.Wrap(err, "verifying SCT")
	}
	fmt.Fprintln(os.Stderr, "Successfully verified SCT...")

	return fs, nil
}
