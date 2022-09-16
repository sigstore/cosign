package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/letsencrypt/boulder/test/ocsp/helper"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `
checkocsp [OPTION]... FILE [FILE]...

OCSP-checking tool. Provide a list of filenames for certificates in PEM format,
and this tool will check OCSP for each certificate based on its AIA field.
It will return an error if the OCSP server fails to respond for any request,
if any response is invalid or has a bad signature, or if any response is too
stale.

`)
		flag.PrintDefaults()
	}
	flag.Parse()
	var errors bool
	if len(flag.Args()) == 0 {
		flag.Usage()
		os.Exit(0)
	}
	for _, f := range flag.Args() {
		_, err := helper.ReqFile(f, helper.ConfigFromFlags())
		if err != nil {
			log.Printf("error for %s: %s\n", f, err)
			errors = true
		}
	}
	if errors {
		os.Exit(1)
	}
}
