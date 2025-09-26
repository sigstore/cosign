// Copyright 2023 The Sigstore Authors.
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

package templates

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"
	"unicode"

	"github.com/sigstore/cosign/v3/cmd/cosign/cli/templates/term"
	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
)

type templater struct {
	UsageTemplate string
	RootCmd       *cobra.Command
}

func SetCustomUsageFunc(cmd *cobra.Command) {
	if cmd == nil {
		panic("nil root command")
	}
	t := &templater{
		RootCmd:       cmd,
		UsageTemplate: MainUsageTemplate(),
	}

	cmd.SetUsageFunc(t.UsageFunc())
}

func (templater *templater) UsageFunc() func(*cobra.Command) error {
	return func(c *cobra.Command) error {
		t := template.New("usage")
		t.Funcs(templater.templateFuncs())
		template.Must(t.Parse(templater.UsageTemplate))
		out := term.NewResponsiveWriter(c.OutOrStderr())
		return t.Execute(out, c)
	}
}

func (templater *templater) templateFuncs() template.FuncMap {
	return template.FuncMap{
		"trim":                    strings.TrimSpace,
		"trimRightSpace":          trimRightSpace,
		"trimTrailingWhitespaces": trimRightSpace,
		"appendIfNotPresent":      appendIfNotPresent,
		"rpad":                    rpad,
		"gt":                      cobra.Gt,
		"eq":                      cobra.Eq,
		"flagsUsages":             flagsUsages,
	}
}

func trimRightSpace(s string) string {
	return strings.TrimRightFunc(s, unicode.IsSpace)
}

// appendIfNotPresent will append stringToAppend to the end of s, but only if it's not yet present in s.
func appendIfNotPresent(s, stringToAppend string) string {
	if strings.Contains(s, stringToAppend) {
		return s
	}
	return s + " " + stringToAppend
}

// rpad adds padding to the right of a string.
func rpad(s string, padding int) string {
	template := fmt.Sprintf("%%-%ds", padding)
	return fmt.Sprintf(template, s)
}

// flagsUsages will print out the kubectl help flags
func flagsUsages(f *flag.FlagSet) (string, error) {
	flagBuf := new(bytes.Buffer)
	wrapLimit, err := term.GetWordWrapperLimit()
	if err != nil {
		return "", err
	}
	printer := NewHelpFlagPrinter(flagBuf, wrapLimit)

	f.VisitAll(func(flag *flag.Flag) {
		if flag.Hidden {
			return
		}
		printer.PrintHelpFlag(flag)
	})

	return flagBuf.String(), nil
}
