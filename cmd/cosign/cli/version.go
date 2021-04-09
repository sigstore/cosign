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
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"runtime"
	"strings"
	"text/tabwriter"

	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/pkg/errors"
)

// Base version information.
//
// This is the fallback data used when version information from git is not
// provided via go ldflags (e.g. via Makefile).
var (
	// Output of "git describe". The prerequisite is that the branch should be
	// tagged using the correct versioning strategy.
	gitVersion = "unknown"
	// SHA1 from git, output of $(git rev-parse HEAD)
	gitCommit = "unknown"
	// State of git tree, either "clean" or "dirty"
	gitTreeState = "unknown"
	// Build date in ISO8601 format, output of $(date -u +'%Y-%m-%dT%H:%M:%SZ')
	buildDate = "unknown"
)

func Version() *ffcli.Command {
	var (
		flagset = flag.NewFlagSet("cosign version", flag.ExitOnError)
		outJSON = flagset.Bool("json", false, "print JSON instead of text")
	)
	return &ffcli.Command{
		Name:       "version",
		ShortUsage: "cosign version",
		ShortHelp:  "Prints the cosign version",
		FlagSet:    flagset,
		Exec: func(ctx context.Context, args []string) error {
			v := VersionInfo()
			res := v.String()
			if *outJSON {
				j, err := v.JSONString()
				if err != nil {
					return errors.Wrap(err, "unable to generate JSON from version info")
				}
				res = j
			}

			fmt.Println(res)
			return nil
		},
	}
}

type Info struct {
	GitVersion   string
	GitCommit    string
	GitTreeState string
	BuildDate    string
	GoVersion    string
	Compiler     string
	Platform     string
}

func VersionInfo() Info {
	// These variables typically come from -ldflags settings and in
	// their absence fallback to the global defaults set above.
	return Info{
		GitVersion:   gitVersion,
		GitCommit:    gitCommit,
		GitTreeState: gitTreeState,
		BuildDate:    buildDate,
		GoVersion:    runtime.Version(),
		Compiler:     runtime.Compiler,
		Platform:     fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
	}
}

// String returns the string representation of the version info
func (i *Info) String() string {
	b := strings.Builder{}
	w := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)

	fmt.Fprintf(w, "GitVersion:\t%s\n", i.GitVersion)
	fmt.Fprintf(w, "GitCommit:\t%s\n", i.GitCommit)
	fmt.Fprintf(w, "GitTreeState:\t%s\n", i.GitTreeState)
	fmt.Fprintf(w, "BuildDate:\t%s\n", i.BuildDate)
	fmt.Fprintf(w, "GoVersion:\t%s\n", i.GoVersion)
	fmt.Fprintf(w, "Compiler:\t%s\n", i.Compiler)
	fmt.Fprintf(w, "Platform:\t%s\n", i.Platform)

	w.Flush()
	return b.String()
}

// JSONString returns the JSON representation of the version info
func (i *Info) JSONString() (string, error) {
	b, err := json.MarshalIndent(i, "", "  ")
	if err != nil {
		return "", err
	}

	return string(b), nil
}
