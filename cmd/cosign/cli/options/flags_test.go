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

package options

import "testing"

func TestOneOf(t *testing.T) {
	type dumbStruct struct {
		A int
		B []string
		C bool
	}
	tests := []struct {
		name string
		args []any
		want bool
	}{
		{
			name: "3/3",
			args: []any{"one", 2, true},
			want: false,
		},
		{
			name: "2/3",
			args: []any{"one", 2, false},
			want: false,
		},
		{
			name: "1/3",
			args: []any{"", 2, false},
			want: true,
		},
		{
			name: "0/1",
			args: []any{""},
			want: false,
		},
		{
			name: "1/1",
			args: []any{"hey"},
			want: true,
		},
		{
			name: "structs",
			args: []any{"hey", dumbStruct{A: 2}},
			want: false,
		},
		{
			name: "struct",
			args: []any{"", dumbStruct{A: 2}},
			want: true,
		},
		{
			name: "pointers",
			args: []any{"hey", &struct{ a int }{a: 2}, false},
			want: false,
		},
		{
			name: "pointer",
			args: []any{&struct{ a int }{a: 2}, false},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := OneOf(tt.args...); got != tt.want {
				t.Errorf("OneOf() = %v, want %v", got, tt.want)
			}
		})
	}
}
