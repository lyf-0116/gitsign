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
	"fmt"
	"time"

	"github.com/sigstore/rekor/pkg/generated/models"
)

// ErrIntegratedTimeOutsideValidity is returned when a Rekor log entry's
// integrated time falls outside the signing certificate's validity window.
// A signature that only appears in the log after the certificate expired
// cannot have been authenticated by that certificate.
var ErrIntegratedTimeOutsideValidity = errors.New("rekor integrated time is outside the certificate validity window")

// ErrNoIntegratedTime is returned when a log entry carries no integrated
// time. Current Rekor entries always include one, but entries reconstructed
// from older signatures (or malformed data) may not; such entries cannot
// pin a verification time and must be handled explicitly by the caller.
var ErrNoIntegratedTime = errors.New("rekor log entry has no integrated time")

// IntegratedTime returns the log entry's integrated (inclusion) time as a
// time.Time, or ErrNoIntegratedTime if the entry does not carry one.
func IntegratedTime(entry *models.LogEntryAnon) (time.Time, error) {
	if entry == nil || entry.IntegratedTime == nil {
		return time.Time{}, ErrNoIntegratedTime
	}
	return time.Unix(*entry.IntegratedTime, 0).UTC(), nil
}

// CheckIntegratedTime asserts that the entry's integrated time lies within
// the certificate's validity window (NotBefore <= t <= NotAfter). This is
// the check that actually intersects the attested signing time with the
// certificate's lifetime: without it, a private key used after the cert
// expired still produces signatures whose chain verifies.
//
// Entries without an integrated time return ErrNoIntegratedTime so callers
// can apply an explicit per-entry-type fallback rather than silently
// defaulting to a time inside the cert's own window.
func CheckIntegratedTime(cert *x509.Certificate, entry *models.LogEntryAnon) (time.Time, error) {
	t, err := IntegratedTime(entry)
	if err != nil {
		return time.Time{}, err
	}
	if t.Before(cert.NotBefore) || t.After(cert.NotAfter) {
		return t, fmt.Errorf("%w: integrated time %s not in [%s, %s]",
			ErrIntegratedTimeOutsideValidity, t.UTC().Format(time.RFC3339),
			cert.NotBefore.UTC().Format(time.RFC3339), cert.NotAfter.UTC().Format(time.RFC3339))
	}
	return t, nil
}
