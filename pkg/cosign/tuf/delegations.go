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

package tuf

import (
	"github.com/pkg/errors"
	tuft "github.com/theupdateframework/go-tuf/pkg/targets"
	"github.com/theupdateframework/go-tuf/verify"
)

// GetDelegationByPath finds a terminating delegation that matches the target path.
func (t *TUF) GetDelegationByPath(path string) (tuft.Delegation, error) {
	// Iterate to find a terminating delegation glob-matching the path.
	// e.g. If an image name is gcr.io/dlorenc/vm-test, this will return a terminating
	// delegation role for the path gcr.io/dlorenc/vm-**.

	snapshot, err := t.GetSnapshot()
	if err != nil {
		return tuft.Delegation{}, err
	}

	delegations := tuft.NewDelegationsIterator(path, t.client.DB())
	for i := 0; i < t.client.MaxDelegations; i++ {
		d, ok := delegations.Next()
		if !ok {
			return tuft.Delegation{}, errors.New("no matching delegation found")
		}

		// return if this is a terminating delegation matching the path
		if d.Delegatee.Terminating {
			return d, nil
		}

		targets, err := t.client.LoadDelegatedTargets(snapshot, d.Delegatee.Name, d.DB)
		if err != nil {
			return tuft.Delegation{}, err
		}

		if targets.Delegations != nil {
			delegationsVerifier, err := verify.NewDBFromDelegations(targets.Delegations)
			if err != nil {
				return tuft.Delegation{}, err
			}
			err = delegations.Add(targets.Delegations.Roles, d.Delegatee.Name, delegationsVerifier)
			if err != nil {
				return tuft.Delegation{}, err
			}
		}
	}

	return tuft.Delegation{}, nil
}
