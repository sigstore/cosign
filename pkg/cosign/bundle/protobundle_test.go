// Copyright 2024 The Sigstore Authors.
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

package bundle

import (
	"testing"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/sigstore/rekor/pkg/generated/models"
	_ "github.com/sigstore/rekor/pkg/types/hashedrekord"
	_ "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
)

func TestMakeProtobufBundle(t *testing.T) {
	testCases := []struct {
		name           string
		hint           string
		rawCert        []byte
		rekorEntry     *models.LogEntryAnon
		timestampBytes []byte
	}{
		{
			name:           "hint with timestamp",
			hint:           "asdf",
			rawCert:        []byte{},
			rekorEntry:     nil,
			timestampBytes: []byte("timestamp"),
		},
		{
			name:           "only cert",
			hint:           "",
			rawCert:        []byte("cert stuff"),
			rekorEntry:     nil,
			timestampBytes: []byte{},
		},
		{
			name:    "cert with rekor entry",
			hint:    "",
			rawCert: []byte("cert stuff"),
			rekorEntry: &models.LogEntryAnon{
				Body:           "eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiaGFzaGVkcmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiI2MmQwOGYyOGM2OWNhZGE3YjQyYTQ1Nzk0YjQ3ZWU2YzgxYTdkZmE3MTY4NDZiMzljODhmMGFkMTljMjA2OTk3In19LCJzaWduYXR1cmUiOnsiY29udGVudCI6Ik1FVUNJQm14U0N1TW1HSzhNQWRMd1FWZ21TZjVXKzlkdU5iQXN1cUNQNlNucUxCUkFpRUFvNGtGRVdDTG9HcTVUaysrUEhtTEgrb3N1emVTRjN4OTdBbmVicTRlbVRvPSIsInB1YmxpY0tleSI6eyJjb250ZW50IjoiTFMwdExTMUNSVWRKVGlCRFJWSlVTVVpKUTBGVVJTMHRMUzB0Q2sxSlNVUk1ha05EUVhKVFowRjNTVUpCWjBsVVRWQkRlVXdyYmxOb2MycHdaa2hZYUZkYVRVWkNUVUZIUlVSQlMwSm5aM0ZvYTJwUFVGRlJSRUY2UVhFS1RWSlZkMFYzV1VSV1VWRkxSWGQ0ZW1GWFpIcGtSemw1V2xNMWExcFlXWGhGVkVGUVFtZE9Wa0pCVFZSRFNFNXdXak5PTUdJelNteE5RalJZUkZSSmVRcE5SRWwzVFdwRmQwNUVXWGhOVm05WVJGUkplVTFFU1hkTmFrVjNUbFJaZUUxR2IzZEZla1ZTVFVFNFIwRXhWVVZEYUUxSll6SnNibU16VW5aamJWVjNDbGRVUVZSQ1oyTnhhR3RxVDFCUlNVSkNaMmR4YUd0cVQxQlJUVUpDZDA1RFFVRlVVMVJ2VEhWS2N5OTFSV05IU2tRME5VWmFiVE5wWmxKTU4yOXVRVWNLWlZaNWJuWkhVbmN6WnpKMU0wbFhTREZuU2tSamNERjRSWFI2UVZCUWJYQmhlVGRtTmxCNE1XeFpNa0ZyWnpsMGEyb3dRa1J2UTNkdk5FbENlbXBEUXdwQlkyOTNSR2RaUkZaU01GQkJVVWd2UWtGUlJFRm5aVUZOUWsxSFFURlZaRXBSVVUxTlFXOUhRME56UjBGUlZVWkNkMDFFVFVGM1IwRXhWV1JGZDBWQ0NpOTNVVU5OUVVGM1NGRlpSRlpTTUU5Q1FsbEZSazlSYTNZNVoyMVpXVFpWU0doQ1pWSnJMMWx4VlVsaU1WRldiMDFDT0VkQk1WVmtTWGRSV1UxQ1lVRUtSa1pxUVVoc0sxSlNZVlp0Y1ZoeVRXdExSMVJKZEVGeGVHTllOazFIVFVkQk1WVmtSVkZTWTAxR2NVZFhSMmd3WkVoQ2VrOXBPSFphTW13d1lVaFdhUXBNYlU1MllsTTVjbGx1VGpCTU0xSnNZMjVLYUZwdE9YbGlVekZ5WkZkS2JHTXpVbWhaTW5OMlRHMWtjR1JIYURGWmFUa3pZak5LY2xwdGVIWmtNMDEyQ21KWFJuQmlhVFUxWWxkNFFXTnRWbTFqZVRsdldsZEdhMk41T1hSWldFNHdXbGhKZDBWbldVdExkMWxDUWtGSFJIWjZRVUpCWjFGRlkwaFdlbUZFUVcwS1FtZHZja0puUlVWQldVOHZUVUZGUmtKQ2FISlpiazR3VEROU2JHTnVTbWhhYlRsNVlsTXhjbVJYU214ak0xSm9XVEp6ZDA1bldVdExkMWxDUWtGSFJBcDJla0ZDUVhkUmIxcHFSVEZPVjFGNVdXMUplRTU2V210TlZFVTFXV3BHYlU5VVNUSk9WRlV6V1hwTk5WbDZTbWxQVkdzMVdtcFNhRnBxWjNkWmVrRTFDa0puYjNKQ1owVkZRVmxQTDAxQlJVSkNRM1J2WkVoU2QyTjZiM1pNTTFKMllUSldkVXh0Um1wa1IyeDJZbTVOZFZveWJEQmhTRlpwWkZoT2JHTnRUbllLWW01U2JHSnVVWFZaTWpsMFRVSTRSME5wYzBkQlVWRkNaemM0ZDBGUldVVkZXRXBzV201TmRtRkhWbWhhU0UxMllsZEdlbVJIVm5sTlEwRkhRMmx6UndwQlVWRkNaemM0ZDBGUlVVVkZhMG94WVZkNGEwbEdVbXhqTTFGblZVaFdhV0pIYkhwaFJFRkxRbWRuY1docmFrOVFVVkZFUVhkT2IwRkVRbXhCYWtWQkNtdDJORTFLYUdGRGFFMUJaMHBWVTNWWll6bFBWRWt3WTB0bU9XTnlObU14Y1RreVYyOXFMM1ZsV0RKRFR6Z3JMMDQyU25SM1FVNTRVSElyTjNWNlpGQUtRV3BDYVhwR2NHZEVMelJzWW5aa1NuRnplWE5HYlVSeU1TdFNNSGhKWjI1S1N5c3JaWGROYmtKaVMxQkVMemd3VTNJelFYTTVMMWxxV1U5M05EVjRkUXA2ZVdzOUNpMHRMUzB0UlU1RUlFTkZVbFJKUmtsRFFWUkZMUzB0TFMwSyJ9fX19",
				IntegratedTime: swag.Int64(123),
				LogID:          swag.String("deadbeef"),
				LogIndex:       swag.Int64(2),
				Verification: &models.LogEntryAnonVerification{
					InclusionProof: &models.InclusionProof{
						Checkpoint: swag.String("checkpoint"),
						Hashes:     []string{"deadbeef", "abcdefaa"},
						LogIndex:   swag.Int64(1),
						RootHash:   swag.String("abcdefaa"),
						TreeSize:   swag.Int64(2),
					},
					SignedEntryTimestamp: strfmt.Base64("set"),
				},
			},
			timestampBytes: []byte{},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			bundle, err := MakeProtobufBundle(tc.hint, tc.rawCert, tc.rekorEntry, tc.timestampBytes)
			if err != nil {
				t.Errorf("unexpected err %s", err)
			}
			if tc.hint != "" && bundle.VerificationMaterial.GetPublicKey() == nil {
				t.Errorf("Verification material should be public key")
			}
			if len(tc.rawCert) > 0 && bundle.VerificationMaterial.GetCertificate() == nil {
				t.Errorf("Verification material should be certificate")
			}
			if tc.rekorEntry != nil && len(bundle.VerificationMaterial.GetTlogEntries()) == 0 {
				t.Errorf("Verification material should contain Tlog Entries")
			}
			if len(tc.timestampBytes) > 0 && bundle.VerificationMaterial.GetTimestampVerificationData() == nil {
				t.Errorf("Verification material should have timestamp")
			}
		})
	}
}
