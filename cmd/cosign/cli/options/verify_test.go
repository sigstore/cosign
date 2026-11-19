//
// Copyright 2026 The Sigstore Authors.
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

package options

import (
	"testing"

	"github.com/spf13/cobra"
)

func TestResolveThresholds(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		args                    []string
		wantIgnoreTlog          bool
		wantUseSignedTimestamps bool
		wantRekorThreshold      int
		wantTimestampThreshold  int
		wantErr                 bool
	}{
		{
			name:               "defaults",
			wantRekorThreshold: 1, wantTimestampThreshold: 0,
		},
		{
			name:               "rekor threshold 0",
			args:               []string{"--rekor-threshold=0"},
			wantIgnoreTlog:     true,
			wantRekorThreshold: 0, wantTimestampThreshold: 0,
		},
		{
			name:               "rekor threshold 2",
			args:               []string{"--rekor-threshold=2"},
			wantRekorThreshold: 2, wantTimestampThreshold: 0,
		},
		{
			name:                    "timestamp threshold 1",
			args:                    []string{"--timestamp-threshold=1"},
			wantUseSignedTimestamps: true,
			wantRekorThreshold:      1, wantTimestampThreshold: 1,
		},
		{
			name:               "timestamp threshold 0",
			args:               []string{"--timestamp-threshold=0"},
			wantRekorThreshold: 1, wantTimestampThreshold: 0,
		},
		{
			name:               "deprecated insecure-ignore-tlog",
			args:               []string{"--insecure-ignore-tlog"},
			wantIgnoreTlog:     true,
			wantRekorThreshold: 0, wantTimestampThreshold: 0,
		},
		{
			name:               "deprecated private-infrastructure",
			args:               []string{"--private-infrastructure"},
			wantIgnoreTlog:     true,
			wantRekorThreshold: 0, wantTimestampThreshold: 0,
		},
		{
			name:                    "deprecated use-signed-timestamps",
			args:                    []string{"--use-signed-timestamps"},
			wantUseSignedTimestamps: true,
			wantRekorThreshold:      1, wantTimestampThreshold: 0,
		},
		{
			name:    "negative rekor threshold",
			args:    []string{"--rekor-threshold=-1"},
			wantErr: true,
		},
		{
			name:    "negative timestamp threshold",
			args:    []string{"--timestamp-threshold=-1"},
			wantErr: true,
		},
		{
			name:    "private-infrastructure with non-zero rekor threshold",
			args:    []string{"--private-infrastructure", "--rekor-threshold=1"},
			wantErr: true,
		},
		{
			name:    "rekor threshold with insecure-ignore-tlog",
			args:    []string{"--rekor-threshold=1", "--insecure-ignore-tlog"},
			wantErr: true,
		},
		{
			name:    "timestamp threshold with use-signed-timestamps",
			args:    []string{"--timestamp-threshold=0", "--use-signed-timestamps"},
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := &CommonVerifyOptions{}
			cmd := &cobra.Command{}
			o.AddFlags(cmd)
			err := cmd.ParseFlags(tc.args)
			if err == nil {
				err = cmd.ValidateFlagGroups()
			}
			if err == nil {
				err = o.ResolveThresholds(cmd.Flags())
			}
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if o.IgnoreTlog != tc.wantIgnoreTlog {
				t.Errorf("IgnoreTlog = %v, want %v", o.IgnoreTlog, tc.wantIgnoreTlog)
			}
			if o.UseSignedTimestamps != tc.wantUseSignedTimestamps {
				t.Errorf("UseSignedTimestamps = %v, want %v", o.UseSignedTimestamps, tc.wantUseSignedTimestamps)
			}
			if o.RekorThreshold != tc.wantRekorThreshold {
				t.Errorf("RekorThreshold = %d, want %d", o.RekorThreshold, tc.wantRekorThreshold)
			}
			if o.TimestampThreshold != tc.wantTimestampThreshold {
				t.Errorf("TimestampThreshold = %d, want %d", o.TimestampThreshold, tc.wantTimestampThreshold)
			}
		})
	}
}
