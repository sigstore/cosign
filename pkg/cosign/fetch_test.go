/*
Copyright The Rekor Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cosign

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

var cert1 = `-----BEGIN CERTIFICATE-----
MIICyTCCAlCgAwIBAgITYZXhosLz4+Q/XCUwBySVDmU2jTAKBggqhkjOPQQDAzAq
MRUwEwYDVQQKEwxzaWdzdG9yZS5kZXYxETAPBgNVBAMTCHNpZ3N0b3JlMB4XDTIx
MDMwOTA0NDYwOVoXDTIxMDMwOTA1MDYwMlowOjEbMBkGA1UECgwSbG9yZW5jLmRA
Z21haWwuY29tMRswGQYDVQQDDBJsb3JlbmMuZEBnbWFpbC5jb20wdjAQBgcqhkjO
PQIBBgUrgQQAIgNiAARIA8thgk3Zext2UWP1aBE1uoIAqetevPiEDuGKtSUPYxBv
AhzrwhDTbHrj6vMQCBNE7o4AfewyJAZf6CKbee8WIakPfAjRSTQjjnZBzKvSHn4K
u8SByXjFN0rde8qDqo+jggEmMIIBIjAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAww
CgYIKwYBBQUHAwMwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUQeDktDb9QFrYxF8H
xBXkAHQmvqwwHwYDVR0jBBgwFoAUyMUdAEGaJCkyUSTrDa5K7UoG0+wwgY0GCCsG
AQUFBwEBBIGAMH4wfAYIKwYBBQUHMAKGcGh0dHA6Ly9wcml2YXRlY2EtY29udGVu
dC02MDNmZTdlNy0wMDAwLTIyMjctYmY3NS1mNGY1ZTgwZDI5NTQuc3RvcmFnZS5n
b29nbGVhcGlzLmNvbS9jYTM2YTFlOTYyNDJiOWZjYjE0Ni9jYS5jcnQwHQYDVR0R
BBYwFIESbG9yZW5jLmRAZ21haWwuY29tMAoGCCqGSM49BAMDA2cAMGQCMAgjOcjN
P3w/xB8bi/hKXJ9RdNH/DMADiusGtd1d/xxyFVj1xYosQ7y1G6y84VDBvQIwMfQG
8Tp8zsxDg5Oz4qUBZ/AKmkPJHhgmiHftwbb5I1S+1xdhzJtJ8Eg0M00/nqok
-----END CERTIFICATE-----
`

var cert2 = `-----BEGIN CERTIFICATE-----
MIICyzCCAlGgAwIBAgIUAMtHjhf/mTVArZNaNcBC1UDyDa0wCgYIKoZIzj0EAwMw
KjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0y
MTAzMDkwNDQ3MTFaFw0yMTAzMDkwNTA3MDNaMDoxGzAZBgNVBAoMEmxvcmVuYy5k
QGdtYWlsLmNvbTEbMBkGA1UEAwwSbG9yZW5jLmRAZ21haWwuY29tMHYwEAYHKoZI
zj0CAQYFK4EEACIDYgAERYBuXY15kRDrwW6kpfwbp/5DmrnGnaZLvUwG1QVGV4g7
/dqNNoXpOU0TstLFSsawgc5YvcgKOw52EGBg5Fi9kUslF1M6bsAarMSTeZl7pzHb
sh8B8+U/jn2HZtfCzalvo4IBJjCCASIwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQM
MAoGCCsGAQUFBwMDMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFK2qQ8zm+0Yz5KM8
6ybuUZPrAVX7MB8GA1UdIwQYMBaAFMjFHQBBmiQpMlEk6w2uSu1KBtPsMIGNBggr
BgEFBQcBAQSBgDB+MHwGCCsGAQUFBzAChnBodHRwOi8vcHJpdmF0ZWNhLWNvbnRl
bnQtNjAzZmU3ZTctMDAwMC0yMjI3LWJmNzUtZjRmNWU4MGQyOTU0LnN0b3JhZ2Uu
Z29vZ2xlYXBpcy5jb20vY2EzNmExZTk2MjQyYjlmY2IxNDYvY2EuY3J0MB0GA1Ud
EQQWMBSBEmxvcmVuYy5kQGdtYWlsLmNvbTAKBggqhkjOPQQDAwNoADBlAjA6Nk0l
eD2ey2UnPUcH6gklWo2szEobbv+uEKPYFzZ8fQn3v7nIdz8p3oSajT2oxFMCMQCQ
zisxAae2OlC3p3RbPuobGVvKI6EYmfnohdvD5OgZPRskNhGAiR2e3MDQuuexbAw=
-----END CERTIFICATE-----
`

var cert3 = `-----BEGIN OTHER THING-----
MIICyjCCAlGgAwIBAgIUAJ7YnfKI0PIi90IkP1ZGVt1hbswwCgYIKoZIzj0EAwMw
KjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0y
MTAzMDkwNDQ4MDJaFw0yMTAzMDkwNTA3NTVaMDoxGzAZBgNVBAoMEmxvcmVuYy5k
QGdtYWlsLmNvbTEbMBkGA1UEAwwSbG9yZW5jLmRAZ21haWwuY29tMHYwEAYHKoZI
zj0CAQYFK4EEACIDYgAEPFq3DlRqPtYRM2XF7eKw4pZFCIo3i1mBTFNzQRL/GufH
G+bQuF9D9qDWwD2sFLDauzTbaIUvpxEdu0ab0rYi0x1sV/RLyZhc7KmpFxGuPEkr
agrlBGDUnxXkUj53NGLCo4IBJjCCASIwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQM
MAoGCCsGAQUFBwMDMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFOYy000hj60o55n3
yX/sE3Kbk65NMB8GA1UdIwQYMBaAFMjFHQBBmiQpMlEk6w2uSu1KBtPsMIGNBggr
BgEFBQcBAQSBgDB+MHwGCCsGAQUFBzAChnBodHRwOi8vcHJpdmF0ZWNhLWNvbnRl
bnQtNjAzZmU3ZTctMDAwMC0yMjI3LWJmNzUtZjRmNWU4MGQyOTU0LnN0b3JhZ2Uu
Z29vZ2xlYXBpcy5jb20vY2EzNmExZTk2MjQyYjlmY2IxNDYvY2EuY3J0MB0GA1Ud
EQQWMBSBEmxvcmVuYy5kQGdtYWlsLmNvbTAKBggqhkjOPQQDAwNnADBkAjAYFQVj
6qsh4cQ05NDOOCBrIdwtaYuiQHCy6y/+0ujrJG8prwc7zx+mFsL0Fsd9g/QCMGZq
vn2snyjRWmm8kGr62QR0T6TKIElf07EmdrAglZodYXcHhv0b0JUmdTnn30vRDQ==
-----BEGIN OTHER THING-----
`

func Test_loadCerts(t *testing.T) {
	type args struct {
		pemStr string
	}
	tests := []struct {
		name    string
		args    args
		want    int
		wantErr bool
	}{
		{
			name: "one",
			args: args{
				pemStr: cert1,
			},
			want: 1,
		},
		{
			name: "two",
			args: args{
				pemStr: cert1 + cert2,
			},
			want: 2,
		},
		{
			name: "onebad",
			args: args{
				pemStr: cert1 + cert3,
			},
			want: 1,
		},
		{
			name: "bad",
			args: args{
				pemStr: cert3,
			},
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := loadCerts(tt.args.pemStr)
			if (err != nil) != tt.wantErr {
				t.Errorf("loadCerts() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if d := cmp.Diff(tt.want, len(got)); d != "" {
				t.Errorf("diff: %s", d)
			}
		})
	}
}
