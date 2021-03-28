package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/uber/makisu/lib/parser/dockerfile"
)

func main() {
	f := os.Args[1]
	c, err := ioutil.ReadFile(f)
	if err != nil {
		panic(err)
	}
	stages, err := dockerfile.ParseFile(string(c), nil)
	if err != nil {
		panic(err)
	}

	stageNames := map[string]struct{}{}
	for _, s := range stages {
		if s.From.Alias != "" {
			stageNames[s.From.Alias] = struct{}{}
		}
		if _, ok := stageNames[s.From.Image]; ok {
			continue
		}
		ref, err := name.ParseReference(s.From.Image)
		if err != nil {
			panic(err)
		}

		img, err := remote.Image(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
		if err != nil {
			panic(err)
		}
		dgst, err := img.Digest()
		if err != nil {
			panic(err)
		}
		fmt.Println(ref.Context().Digest(dgst.String()))
	}
}
