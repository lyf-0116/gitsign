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
	"context"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/github/smimesign/fakeca"
	"github.com/go-openapi/swag/conv"
	cms "github.com/sigstore/gitsign/internal/fork/ietf-cms"
	"github.com/sigstore/gitsign/internal/signature"
	"github.com/sigstore/gitsign/pkg/rekor"
	"github.com/sigstore/rekor/pkg/generated/models"
)

// mockRekor is a minimal rekor.Verifier for the legacy orchestration test.
// It serves the offline VerifyInclusion path (embedded entries) by default;
// set online to exercise the legacy object-hash path instead.
type mockRekor struct {
	entry  *models.LogEntryAnon
	online bool
}

func (m *mockRekor) VerifyInclusion(_ context.Context, _ []byte, _ *x509.Certificate) (*models.LogEntryAnon, error) {
	if m.online {
		return nil, errors.New("no embedded entry")
	}
	return m.entry, nil
}

func (m *mockRekor) Verify(_ context.Context, _ string, _ *x509.Certificate) (*models.LogEntryAnon, error) {
	return m.entry, nil
}

func (m *mockRekor) Search(_ context.Context, _ string, _ *x509.Certificate) (*models.LogEntryAnon, error) {
	return m.entry, nil
}

var _ rekor.Verifier = (*mockRekor)(nil)

// signingFixture builds a detached CMS signature over data plus a
// CertVerifier that trusts its (fake) CA. The cert validity window is
// [notBefore, notAfter].
type signingFixture struct {
	data     []byte
	sig      []byte
	verifier Verifier
}

func newSigningFixture(t *testing.T, notBefore, notAfter time.Time) signingFixture {
	t.Helper()
	ctx := context.Background()

	ca := fakeca.New(fakeca.IsCA)
	signer := ca.Issue(fakeca.NotBefore(notBefore), fakeca.NotAfter(notAfter))
	roots := x509.NewCertPool()
	roots.AddCert(ca.Certificate)

	// Commit-shaped body so the legacy object-hash reconstruction
	// (ObjectHashFromSignature) can infer the object type.
	data := []byte("tree 0123456789012345678901234567890123456789\n" +
		"author Alice <alice@example.com> 1700000000 +0000\n" +
		"committer Alice <alice@example.com> 1700000000 +0000\n\nhello\n")
	id := &identity{base: signer}
	resp, err := signature.Sign(ctx, id, data, signature.SignOptions{
		Detached:     true,
		Armor:        true,
		IncludeCerts: 0,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	cv, err := NewCertVerifier(WithRootPool(roots))
	if err != nil {
		t.Fatalf("NewCertVerifier: %v", err)
	}

	return signingFixture{data: data, sig: resp.Signature, verifier: cv}
}

// TestVerifyIntegratedTimeIntersectsValidity is the regression test for the
// missing signing-time/validity intersection: a log entry integrated after
// the certificate expired must fail, while one inside the window passes.
func TestVerifyIntegratedTimeIntersectsValidity(t *testing.T) {
	ctx := context.Background()

	// The cert is already expired by a day.
	notBefore := time.Now().Add(-48 * time.Hour)
	notAfter := time.Now().Add(-24 * time.Hour)
	fx := newSigningFixture(t, notBefore, notAfter)

	t.Run("integrated inside window passes", func(t *testing.T) {
		entry := &models.LogEntryAnon{
			IntegratedTime: conv.Pointer(notBefore.Add(time.Hour).Unix()),
		}
		if _, err := Verify(ctx, fx.verifier, &mockRekor{entry: entry}, fx.data, fx.sig, true); err != nil {
			t.Fatalf("Verify() = %v; want success", err)
		}
	})

	t.Run("integrated after expiry fails", func(t *testing.T) {
		entry := &models.LogEntryAnon{
			IntegratedTime: conv.Pointer(notAfter.Add(time.Hour).Unix()),
		}
		_, err := Verify(ctx, fx.verifier, &mockRekor{entry: entry}, fx.data, fx.sig, true)
		if !errors.Is(err, ErrIntegratedTimeOutsideValidity) {
			t.Fatalf("Verify() = %v; want ErrIntegratedTimeOutsideValidity", err)
		}
	})

	t.Run("offline entry without integrated time fails rather than defaulting to pass", func(t *testing.T) {
		entry := &models.LogEntryAnon{}
		_, err := Verify(ctx, fx.verifier, &mockRekor{entry: entry}, fx.data, fx.sig, true)
		if !errors.Is(err, ErrNoIntegratedTime) {
			t.Fatalf("Verify() = %v; want ErrNoIntegratedTime", err)
		}
	})
}

// TestVerifyLegacyEntryNoIntegratedTimeDowngrade covers the per-entry-type
// grading: a legacy "online" entry (found via the object-hash lookup) without
// an integrated time is downgraded to an explicit current-time chain check
// instead of being silently verified at a time inside the cert's own window.
// With an expired cert that current-time check must fail.
func TestVerifyLegacyEntryNoIntegratedTimeDowngrade(t *testing.T) {
	ctx := context.Background()

	t.Run("still-valid cert downgrades to current-time check and passes", func(t *testing.T) {
		notBefore := time.Now().Add(-time.Hour)
		notAfter := time.Now().Add(time.Hour)
		fx := newSigningFixture(t, notBefore, notAfter)

		if _, err := Verify(ctx, fx.verifier, &mockRekor{entry: &models.LogEntryAnon{}, online: true}, fx.data, fx.sig, true); err != nil {
			t.Fatalf("Verify() = %v; want success after explicit downgrade", err)
		}
	})

	t.Run("expired cert downgrades to current-time check and fails", func(t *testing.T) {
		notBefore := time.Now().Add(-48 * time.Hour)
		notAfter := time.Now().Add(-24 * time.Hour)
		fx := newSigningFixture(t, notBefore, notAfter)

		_, err := Verify(ctx, fx.verifier, &mockRekor{entry: &models.LogEntryAnon{}, online: true}, fx.data, fx.sig, true)
		if err == nil {
			t.Fatal("Verify() = nil; want validity-window error from explicit downgrade")
		}
		if !errors.Is(err, cms.ErrNoVerificationTime) &&
			!strings.Contains(err.Error(), "expired") &&
			!strings.Contains(err.Error(), "not yet valid") {
			t.Fatalf("Verify() = %v; want a validity-window error", err)
		}
	})
}
