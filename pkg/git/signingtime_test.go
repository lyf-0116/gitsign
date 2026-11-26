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

package git

import (
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/github/smimesign/fakeca"
	"github.com/go-openapi/swag/conv"
	"github.com/sigstore/rekor/pkg/generated/models"
)

// certWithWindow returns a leaf certificate with the given validity window,
// issued by a throwaway fake CA (the same fixture style as signature_test.go).
func certWithWindow(t *testing.T, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	ca := fakeca.New(fakeca.IsCA)
	return ca.Issue(fakeca.NotBefore(notBefore), fakeca.NotAfter(notAfter)).Certificate
}

func TestIntegratedTime(t *testing.T) {
	want := time.Unix(1_700_000_000, 0).UTC()

	for _, tc := range []struct {
		name    string
		entry   *models.LogEntryAnon
		wantErr error
	}{
		{
			name:  "integrated time present",
			entry: &models.LogEntryAnon{IntegratedTime: conv.Pointer(want.Unix())},
		},
		{
			name:    "nil entry",
			entry:   nil,
			wantErr: ErrNoIntegratedTime,
		},
		{
			name:    "missing integrated time",
			entry:   &models.LogEntryAnon{},
			wantErr: ErrNoIntegratedTime,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := IntegratedTime(tc.entry)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("IntegratedTime() error = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr == nil && !got.Equal(want) {
				t.Fatalf("IntegratedTime() = %v, want %v", got, want)
			}
		})
	}
}

func TestCheckIntegratedTime(t *testing.T) {
	notBefore := time.Unix(1_700_000_000, 0)
	notAfter := notBefore.Add(10 * time.Minute)
	cert := certWithWindow(t, notBefore, notAfter)

	for _, tc := range []struct {
		name    string
		entry   *models.LogEntryAnon
		wantErr error
	}{
		{
			name:  "inside window",
			entry: &models.LogEntryAnon{IntegratedTime: conv.Pointer(notBefore.Add(5 * time.Minute).Unix())},
		},
		{
			name:  "at not before boundary",
			entry: &models.LogEntryAnon{IntegratedTime: conv.Pointer(notBefore.Unix())},
		},
		{
			name:  "at not after boundary",
			entry: &models.LogEntryAnon{IntegratedTime: conv.Pointer(notAfter.Unix())},
		},
		{
			name:    "integrated after cert expired",
			entry:   &models.LogEntryAnon{IntegratedTime: conv.Pointer(notAfter.Add(time.Second).Unix())},
			wantErr: ErrIntegratedTimeOutsideValidity,
		},
		{
			name:    "integrated before cert valid",
			entry:   &models.LogEntryAnon{IntegratedTime: conv.Pointer(notBefore.Add(-time.Second).Unix())},
			wantErr: ErrIntegratedTimeOutsideValidity,
		},
		{
			name:    "no integrated time is explicit downgrade, not default pass",
			entry:   &models.LogEntryAnon{},
			wantErr: ErrNoIntegratedTime,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CheckIntegratedTime(cert, tc.entry)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("CheckIntegratedTime() error = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr == nil {
				want := time.Unix(*tc.entry.IntegratedTime, 0).UTC()
				if !got.Equal(want) {
					t.Fatalf("CheckIntegratedTime() = %v, want %v", got, want)
				}
			}
		})
	}
}
