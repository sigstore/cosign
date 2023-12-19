// Copyright 2023 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"sigs.k8s.io/release-utils/version"
)

var (
	expectedVersionInfo = version.GetVersionInfo()
	reGitVersion        = regexp.MustCompile(fmt.Sprintf("\nGitVersion:\\s+%s\n", expectedVersionInfo.GitVersion))
	reGitCommmit        = regexp.MustCompile(fmt.Sprintf("GitCommit:\\s+%s\n", expectedVersionInfo.GitCommit))
	reBuildDate         = regexp.MustCompile(fmt.Sprintf("BuildDate:\\s+%s\n", expectedVersionInfo.BuildDate))
	reGoVersion         = regexp.MustCompile(fmt.Sprintf("GoVersion:\\s+%s\n", expectedVersionInfo.GoVersion))
	reCompiler          = regexp.MustCompile(fmt.Sprintf("Compiler:\\s+%s\n", expectedVersionInfo.Compiler))
	rePlatform          = regexp.MustCompile(fmt.Sprintf("Platform:\\s+%s\n", expectedVersionInfo.Platform))
)

func getVersionSTDOUT(json bool) (bytes.Buffer, error) {
	command := New()
	if json {
		command.SetArgs([]string{"version", "--json"})
	} else {
		command.SetArgs([]string{"version"})

	}
	// testing approach inspired by https://github.com/zenizh/go-capturer/blob/master/main.go
	reader, writer, err := os.Pipe()
	if err != nil {
		return bytes.Buffer{}, errors.New("failed to create a pipe for testing os.Stdout")
	}
	stdout := os.Stdout
	os.Stdout = writer
	err = command.Execute()
	os.Stdout = stdout
	if err != nil {
		return bytes.Buffer{}, errors.New("version is expected to run with a")
	}
	writer.Close()

	var buffer bytes.Buffer
	_, err = io.Copy(&buffer, reader)
	return buffer, err
}

func testVersionASCII(t *testing.T) {
	buffer, err := getVersionSTDOUT(false)
	output := buffer.String()
	assert.NoError(t, err)
	assert.Regexp(t, reGitVersion, output, "output doesn't contain the Git version tag")
	assert.Regexp(t, reGitCommmit, output, "output doesn't contain the Git commit hash")
	assert.Regexp(t, reBuildDate, output, "output doesn't contain the build date")
	assert.Regexp(t, reGoVersion, output, "output doesn't contain the Go version")
	assert.Regexp(t, reCompiler, output, "output doesn't contain the compiler name")
	assert.Regexp(t, rePlatform, output, "output doesn't contain the platform name")
}

func testVersionJSON(t *testing.T) {
	buffer, err := getVersionSTDOUT(true)
	assert.NoError(t, err)
	output := buffer.Bytes()
	var actualVersionInfo version.Info
	err = json.Unmarshal(output, &actualVersionInfo)
	assert.NoError(t, err)
	assert.Equal(t, expectedVersionInfo.GitVersion, actualVersionInfo.GitVersion)
	assert.Equal(t, expectedVersionInfo.GitCommit, actualVersionInfo.GitCommit)
	assert.Equal(t, expectedVersionInfo.BuildDate, actualVersionInfo.BuildDate)
	assert.Equal(t, expectedVersionInfo.GoVersion, actualVersionInfo.GoVersion)
	assert.Equal(t, expectedVersionInfo.Compiler, actualVersionInfo.Compiler)
	assert.Equal(t, expectedVersionInfo.Platform, actualVersionInfo.Platform)
}

func TestVersionOutput(t *testing.T) {
	t.Run("ASCII", testVersionASCII)
	t.Run("JSON", testVersionJSON)
}
