// Copyright 2021 The Rekor Authors
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

package cli

import (
	"context"
	"flag"
	"fmt"
	"runtime"

	"github.com/peterbourgon/ff/v3/ffcli"
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
	)
	return &ffcli.Command{
		Name:       "version",
		ShortUsage: "cosign version",
		ShortHelp:  "Prints the cosign version",
		FlagSet:    flagset,
		Exec: func(ctx context.Context, args []string) error {
			fmt.Printf("%#v\n", versionInfo())
			return nil
		},
	}
}

type VersionInfo struct {
	GitVersion   string
	GitCommit    string
	GitTreeState string
	BuildDate    string
	GoVersion    string
	Compiler     string
	Platform     string
}

func versionInfo() VersionInfo {
	// These variables typically come from -ldflags settings and in
	// their absence fallback to the global defaults set above.
	return VersionInfo{
		GitVersion:   gitVersion,
		GitCommit:    gitCommit,
		GitTreeState: gitTreeState,
		BuildDate:    buildDate,
		GoVersion:    runtime.Version(),
		Compiler:     runtime.Compiler,
		Platform:     fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
	}
}
