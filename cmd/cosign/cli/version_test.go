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
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
)

const cosignDescription = "cosign: A tool for Container Signing, Verification and Storage in an OCI registry."

func TestVersionOutputStream(t *testing.T) {
	command := New()
	command.SetArgs([]string{"version"})
	// testing approach inspired by https://github.com/zenizh/go-capturer/blob/master/main.go
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal("failed to create a pipe for testing os.Stdout")
	}
	stdout := os.Stdout
	os.Stdout = writer
	err = command.Execute()
	os.Stdout = stdout
	if err != nil {
		t.Fatal("version is expected to run with a")
	}
	writer.Close()

	var buffer bytes.Buffer
	_, err = io.Copy(&buffer, reader)
	if err != nil {
		t.Fatal("failed to copy the contents of os.Stdout")
	}
	output := buffer.String()
	if !strings.Contains(output, cosignDescription) {
		fmt.Print(output)
		t.Fatal("version output doesn't contain the expected format")
	}

}
