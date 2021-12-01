package dockerfile

import (
	"bufio"
	"bytes"
	"context"
	"flag"
	"fmt"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/pkg/oci/remote"
	"io"
	"os"
	"strings"

	"github.com/pkg/errors"
)

// ResolveDockerfileCommand rewrites the Dockerfile
// base images to FROM <digest>.
type ResolveDockerfileCommand struct {
	Output string
}

// Exec runs the resolve dockerfile command
func (c *ResolveDockerfileCommand) Exec(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return flag.ErrHelp
	}

	dockerfile, err := os.Open(args[0])
	if err != nil {
		return fmt.Errorf("could not open Dockerfile: %w", err)
	}
	defer dockerfile.Close()

	resolvedDockerfile, err := resolveDigest(dockerfile)
	if err != nil {
		return fmt.Errorf("failed extracting images from Dockerfile: %w", err)
	}

	fmt.Fprintln(os.Stderr, string(resolvedDockerfile))

	return nil
}

func resolveDigest(dockerfile io.Reader) ([]byte, error) {
	fileScanner := bufio.NewScanner(dockerfile)
	tmp := bytes.NewBuffer([]byte{})

	for fileScanner.Scan() {
		line := strings.TrimSpace(fileScanner.Text())

		// TODO(developer-guy): support the COPY --from=image:tag cases
		if strings.HasPrefix(strings.ToUpper(line), "FROM") {
			switch image := getImageFromLine(line); image {
			case "scratch":
				tmp.WriteString(line)
			default:
				ref, err := name.ParseReference(image)
				if err != nil {
					// we should not return err here since
					// we can define the image refs smth like
					// i.e., FROM alpine:$(TAG), FROM $(IMAGE), etc.
					tmp.WriteString(line)
					tmp.WriteString("\n")
					continue
				}

				d, err := remote.ResolveDigest(ref)
				if err != nil {
					return nil, errors.Wrap(err, "resolving digest")
				}

				// rewrite the image as follows:
				// alpine:3.13 => index.docker.io/library/alpine@sha256:026f721af4cf2843e07bba648e158fb35ecc876d822130633cc49f707f0fc88c
				tmp.WriteString(strings.ReplaceAll(line, image, d.String()))
			}
		} else {
			tmp.WriteString(line)
		}
		tmp.WriteString("\n")
	}

	return tmp.Bytes(), nil
}
