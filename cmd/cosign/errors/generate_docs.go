//
// Copyright 2022 The Sigstore Authors.
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

package errors

import (
	"fmt"
	"go/ast"
	godoc "go/doc"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strconv"
	"strings"
)

// GenerateExitCodeDocs will generate documentation for the exit codes
// that the cosign application will throw. Inspired by elemental-cli who
// convieniently solved this problem prior: https://github.com/rancher/elemental-cli/blob/main/docs/generate_docs.go
// there was no need to change (apart from some file paths) due to it
// giving us exactly what we want without error.
func GenerateExitCodeDocs(dir string) error {
	fset := token.NewFileSet()
	files := []*ast.File{
		mustParse(fset, "./cmd/cosign/errors/exit_codes.go"),
	}
	p, err := godoc.NewFromFiles(fset, files, "github.com/sigstore/cosign")
	if err != nil {
		panic(err)
	}
	// nolint prealloc
	var (
		exitCodes []*ErrorCode
		used      map[int]bool
	)

	used = make(map[int]bool)

	for _, c := range p.Consts {
		// Cast it, its safe as these are constants
		v := c.Decl.Specs[0].(*ast.ValueSpec)
		val := v.Values[0].(*ast.BasicLit)
		code, _ := strconv.Atoi(val.Value)

		if _, ok := used[code]; ok {
			return fmt.Errorf("duplicate exit-code found: %v", code)
		}

		used[code] = true
		exitCodes = append(exitCodes, &ErrorCode{code: code, doc: c.Doc})
	}

	sort.Slice(exitCodes, func(i, j int) bool {
		return exitCodes[i].code < exitCodes[j].code
	})

	exitCodesFile, err := os.Create(dir + "/cosign_exit_codes.md")

	if err != nil {
		fmt.Print(err)
		return err
	}

	defer func() {
		_ = exitCodesFile.Close()
	}()

	_, _ = exitCodesFile.WriteString("# Exit codes for cosign CLI\n\n")
	_, _ = exitCodesFile.WriteString("> The following exit codes may be subject to change\n\n")
	_, _ = exitCodesFile.WriteString("| Exit code | Meaning |\n")
	_, _ = exitCodesFile.WriteString("| :----: | :---- |\n")
	for _, code := range exitCodes {
		_, err = fmt.Fprintf(exitCodesFile, "| %d | %s|\n", code.code, strings.Replace(code.doc, "\n", "", 1))
		if err != nil {
			return err
		}
	}

	return nil
}

func mustParse(fset *token.FileSet, filename string) *ast.File {
	f, err := parser.ParseFile(fset, filename, nil, parser.ParseComments)
	if err != nil {
		panic(err)
	}
	return f
}

type ErrorCode struct {
	code int
	doc  string
}
