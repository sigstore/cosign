package attest

import (
	"bytes"
	"context"
	"crypto"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/attestation"
	"github.com/sigstore/cosign/pkg/oci/static"
	"github.com/sigstore/cosign/pkg/types"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
)

func AttestBlobCmd(ctx context.Context, ko options.KeyOpts, artifactPath string, artifactHash string, certPath string, certChainPath string, noUpload bool, predicatePath string, force bool, predicateType string, replace bool, timeout time.Duration) error {
	// A key file or token is required unless we're in experimental mode!
	if options.EnableExperimental() {
		if options.NOf(ko.KeyRef, ko.Sk) > 1 {
			return &options.KeyParseError{}
		}
	} else {
		if !options.OneOf(ko.KeyRef, ko.Sk) {
			return &options.KeyParseError{}
		}
	}

	var artifact []byte
	var hexDigest string
	var err error

	if artifactHash == "" {
		if artifactPath == "-" {
			artifact, err = io.ReadAll(os.Stdin)
		} else {
			fmt.Fprintln(os.Stderr, "Using payload from:", artifactPath)
			artifact, err = os.ReadFile(filepath.Clean(artifactPath))
		}
		if err != nil {
			return err
		} else if timeout != 0 {
			var cancelFn context.CancelFunc
			ctx, cancelFn = context.WithTimeout(ctx, timeout)
			defer cancelFn()
		}
	}

	sv, err := sign.SignerFromKeyOpts(ctx, certPath, certChainPath, ko)
	if err != nil {
		return errors.Wrap(err, "getting signer")
	}
	defer sv.Close()
	//pub, err := sv.PublicKey()
	if err != nil {
		return err
	}
	/*pem, err := cryptoutils.MarshalPublicKeyToPEM(pub)
	if err != nil {
		return errors.Wrap(err, "key to pem")
	}*/

	if timeout != 0 {
		var cancelFn context.CancelFunc
		ctx, cancelFn = context.WithTimeout(ctx, timeout)
		defer cancelFn()
	}

	if artifactHash == "" {
		digest, _, err := signature.ComputeDigestForSigning(bytes.NewReader(artifact), crypto.SHA256, []crypto.Hash{crypto.SHA256, crypto.SHA384})
		if err != nil {
			return err
		}
		hexDigest = strings.ToLower(hex.EncodeToString(digest))
	} else {
		hexDigest = artifactHash
	}
	wrapped := dsse.WrapSigner(sv, types.IntotoPayloadType)

	fmt.Fprintln(os.Stderr, "Using payload from:", predicatePath)
	predicate, err := os.Open(predicatePath)
	if err != nil {
		return err
	}
	defer predicate.Close()

	base := path.Base(artifactPath)

	sh, err := attestation.GenerateStatement(attestation.GenerateOpts{
		Predicate: predicate,
		Type:      predicateType,
		Digest:    hexDigest,
		Repo:      base,
	})
	if err != nil {
		return err
	}

	payload, err := json.Marshal(sh)
	if err != nil {
		return err
	}
	signedPayload, err := wrapped.SignMessage(bytes.NewReader(payload), signatureoptions.WithContext(ctx))
	if err != nil {
		return errors.Wrap(err, "signing")
	}

	if noUpload {
		fmt.Println(string(signedPayload))
		return nil
	}

	opts := []static.Option{static.WithLayerMediaType(types.DssePayloadType)}
	if sv.Cert != nil {
		opts = append(opts, static.WithCertChain(sv.Cert, sv.Chain))
	}

	// Check whether we should be uploading to the transparency log
	if options.EnableExperimental() {
		fmt.Println("Uploading to Rekor")
		/*r, err := rc.GetRekorClient(ko.RekorURL)
		if err != nil {
			return err
		}*/
		_, err := uploadToTlog(ctx, sv, ko.RekorURL, func(r *client.Rekor, b []byte) (*models.LogEntryAnon, error) {
			return cosign.TLogUploadInTotoAttestation(ctx, r, signedPayload, b)
		})
		if err != nil {
			return err
		}
		/*l, err := cosign.TLogUploadInTotoAttestation(ctx, r, signedPayload, pem)
		if err != nil {
			return err
		}*/

		//fmt.Fprintln(os.Stderr, "Log id:", *bundle.LogIndex)
	}
	return err
}
